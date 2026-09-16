rule Win_Trojan_Trivial_167
{
strings:
	$a0 = { ba1c01b44ecd21ba9e00b8013dcd218bd8b440b121ba0001cd21 }


condition:
	$a0
}