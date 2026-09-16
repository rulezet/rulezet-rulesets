rule Win_Trojan_Virut_413
{
strings:
	$a0 = { b5fdfc8d0f10eefcb8764e000087d1f88d12e9d2000000816aaa007cf6f40071564484324dd162e4f7d2 }


condition:
	$a0
}