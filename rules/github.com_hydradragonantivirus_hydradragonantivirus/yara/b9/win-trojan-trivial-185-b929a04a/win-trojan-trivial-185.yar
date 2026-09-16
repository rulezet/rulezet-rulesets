rule Win_Trojan_Trivial_185
{
strings:
	$a0 = { b120b44ecd21ba9e00b8013dcd218bd8b440b124ba0001cd21cd202a2e636f6d00 }


condition:
	$a0
}