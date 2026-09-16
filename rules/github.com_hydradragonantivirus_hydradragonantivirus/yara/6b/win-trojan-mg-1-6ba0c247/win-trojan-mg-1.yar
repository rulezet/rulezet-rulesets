rule Win_Trojan_MG_1
{
strings:
	$a0 = { 1e07585e1ebb000153cb3d044b74 }


condition:
	$a0
}