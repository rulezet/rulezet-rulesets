rule Win_Trojan_ILL_1
{
strings:
	$a0 = { f80383ea2033ff3e8a86f3043e2883 }


condition:
	$a0
}