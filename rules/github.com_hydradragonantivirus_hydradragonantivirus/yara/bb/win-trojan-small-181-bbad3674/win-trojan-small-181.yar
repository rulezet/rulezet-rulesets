rule Win_Trojan_Small_181
{
strings:
	$a0 = { af60b025b34a8ec0b13af3a41f87013c257406ab8cc08701ab0e070e1f5f2bcef3a4ebdb608bf2ac3de940750a1e0e1f99b93a00cd211f61ea }


condition:
	$a0
}