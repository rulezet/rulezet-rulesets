rule Win_Trojan_SouthAfrican2_1
{
strings:
	$a0 = { 8becc746100001e80000582d6300b1 }


condition:
	$a0
}