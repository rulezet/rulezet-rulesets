rule Win_Trojan_FatherMac_1
{
strings:
	$a0 = { 1c0189d2b9790688ed81e91c0180ec00268a02345283c20089f626880283ea0046e2eac3 }


condition:
	$a0
}