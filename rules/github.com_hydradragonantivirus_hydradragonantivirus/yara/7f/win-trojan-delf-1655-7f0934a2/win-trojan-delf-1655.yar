rule Win_Trojan_Delf_1655
{
strings:
	$a0 = { 8d4dec66bad707b8b0c94400e840fcffff8b55ecb8ccfb4400e85775fbff8d4de866bad707b8ecc94400e822fcffff8b55e8b8d0fb4400e83975fbff8b15d0fb4400a1ccfb4400e8a9fcffff84c0742c }


condition:
	$a0
}