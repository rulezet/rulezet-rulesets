rule Win_Trojan_Lecna_1
{
strings:
	$a0 = { 9090558bec6aff6808724000e9a8fdffff00000000000000 }


condition:
	$a0
}