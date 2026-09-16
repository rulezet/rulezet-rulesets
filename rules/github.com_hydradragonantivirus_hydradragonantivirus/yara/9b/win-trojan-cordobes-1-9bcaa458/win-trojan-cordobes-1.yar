rule Win_Trojan_Cordobes_1
{
strings:
	$a0 = { fffc0e0e1f2e8c062f00bf6d7c81c7c483b960f981c6f30081f136ff0751b10aad2d0008d3c0ab59e2f3eb039061 }


condition:
	$a0
}