rule Win_Trojan_Elbas_1
{
strings:
	$a0 = { ffff8b45e88bd3e83afeffff8d55e48b03e830feffff8b55e48bc3e8ead4ffff33c05a595964891068886640008d45e4ba07000000e8a0d4ffffc3e912cfffffebeb5b8be55dc3000000ffffffff130000007369703d }


condition:
	$a0
}