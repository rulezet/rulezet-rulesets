rule Win_Trojan_Trivial_209
{
strings:
	$a0 = { 2101cd217217ba9e00b8023dcd218bd8b127ba0001b440cd21b44febe5c3 }


condition:
	$a0
}