rule Win_Trojan_SouthAfrican408_1
{
strings:
	$a0 = { ecc746100001e80000582d5a0090 }


condition:
	$a0
}