rule Win_Trojan_GU_1
{
strings:
	$a0 = { 0181c503018bfd81c7ba048b1d03dd53c3 }


condition:
	$a0
}