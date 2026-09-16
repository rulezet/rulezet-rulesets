rule Win_Trojan_Trivial_269
{
strings:
	$a0 = { 2701cd21721db43cba9e00cd21b8023dcd218bd8b440b12cba0001cd21b44fcd2173e3c32a2e432a00 }


condition:
	$a0
}