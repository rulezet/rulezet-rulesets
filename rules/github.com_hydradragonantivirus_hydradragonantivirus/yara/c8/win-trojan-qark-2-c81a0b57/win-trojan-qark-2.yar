rule Win_Trojan_Qark_2
{
strings:
	$a0 = { fc83ee0306560e1f0e078b9c040081c62600b9e4038bfead03c3abe2fa5e07 }


condition:
	$a0
}