rule Win_Trojan_Trivial_493
{
strings:
	$a0 = { b44ecd21b43dba9e00b002cd218bd8b93b00ba0001b440cd21ba2501b409cd21cd20 }


condition:
	$a0
}