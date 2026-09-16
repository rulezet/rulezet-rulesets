rule Win_Trojan_Delf_1156
{
strings:
	$a0 = { 556882ed440064ff30648920a174fc4400c60000b898ed4400e894f7ffff84c074788d55ecb801000000e8f7faff }


condition:
	$a0
}