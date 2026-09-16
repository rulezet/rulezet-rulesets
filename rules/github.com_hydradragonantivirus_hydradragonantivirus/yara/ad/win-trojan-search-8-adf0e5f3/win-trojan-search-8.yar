rule Win_Trojan_Search_8
{
strings:
	$a0 = { e800005d83ed06b81b35cd212e8c46582e895e5a0e1f0e078bd583c260b81b25cd210e1fb9ffff0e0733db8bf5 }


condition:
	$a0
}