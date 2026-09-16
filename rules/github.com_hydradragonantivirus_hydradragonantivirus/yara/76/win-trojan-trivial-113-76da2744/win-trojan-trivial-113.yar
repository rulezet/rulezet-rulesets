rule Win_Trojan_Trivial_113
{
strings:
	$a0 = { ba0000b44ecd21ba9e00b8013dcd218bd8b440ba0001cd212a2e2a }


condition:
	$a0
}