rule Win_Trojan_PI_1
{
strings:
	$a0 = { ff8bd8cd213d911e7406909090e9db03e9f904fb9c57 }


condition:
	$a0
}