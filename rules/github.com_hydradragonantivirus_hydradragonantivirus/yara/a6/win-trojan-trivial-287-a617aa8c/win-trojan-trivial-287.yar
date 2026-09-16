rule Win_Trojan_Trivial_287
{
strings:
	$a0 = { 20ba2801cd21ba9e00b8013dcd218bd8ba0001b12eb440cd21b43ecd21b44fcd2173e3cd20 }


condition:
	$a0
}