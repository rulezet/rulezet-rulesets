rule Win_Trojan_ARJ_1
{
strings:
	$a0 = { ec83c4eee88303b8b61450e83e0b50e8450b83c404b8 }


condition:
	$a0
}