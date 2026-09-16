rule Win_Trojan_Splinter_1
{
strings:
	$a0 = { d1b409ba6801cd21cd202a2e636f6d004f7574206f66204d656d6f7279212453706c696e74657220 }


condition:
	$a0
}