rule Win_Trojan__0104_0002_003_1
{
strings:
	$a0 = { a2098bd081c20001b007e8b1015ab440cd21e8c600582d0300a3a202baa102b90400b440cd21 }


condition:
	$a0
}