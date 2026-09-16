rule Win_Trojan_VB_1734
{
strings:
	$a0 = { 6c6f677565000050000000e89b4ebda1424b459e16e054bfa13169 }


condition:
	$a0
}