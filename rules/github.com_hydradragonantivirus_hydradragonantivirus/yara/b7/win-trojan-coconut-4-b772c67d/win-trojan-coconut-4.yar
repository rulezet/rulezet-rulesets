rule Win_Trojan_Coconut_4
{
strings:
	$a0 = { 0374088bf7ad86e0abe2fac3e8a1ffe8e3ffb40b80f4 }


condition:
	$a0
}