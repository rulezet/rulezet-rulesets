rule Win_Trojan_Honerep_1
{
strings:
	$a0 = { 6b6f690048304e33595030372e65786500 }


condition:
	$a0
}