rule Win_Trojan_Slovakia_3
{
strings:
	$a0 = { 0300578bf71e0e1f0e07fcb9b707ac32c4aa80c411e2f7 }


condition:
	$a0
}