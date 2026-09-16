rule Win_Trojan_XMB_823_1
{
strings:
	$a0 = { e8c3ffb44033d2b93703e80700be6800e8b3ffc39c }


condition:
	$a0
}