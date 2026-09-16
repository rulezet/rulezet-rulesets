rule Win_Trojan_Trivial_426
{
strings:
	$a0 = { ba9e00b8013dcd218bd8b440b97400ba0001cd21720ab43ecd21b44fcd2173e0b409ba3201cd21cd }


condition:
	$a0
}