rule Win_Trojan_Runner_1
{
strings:
	$a0 = { 57bf6c261e57ff360eb331c050509a2d0a16019af4041601813e0eb3a08c74c0bf90b31e }


condition:
	$a0
}