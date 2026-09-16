rule Win_Trojan_Destroy_1
{
strings:
	$a0 = { 57bf0c331e57b8f0115031c050509a74086500bf }


condition:
	$a0
}