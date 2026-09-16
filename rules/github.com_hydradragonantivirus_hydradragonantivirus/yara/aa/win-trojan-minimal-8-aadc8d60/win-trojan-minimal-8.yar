rule Win_Trojan_Minimal_8
{
strings:
	$a0 = { ba0001b12eb440cd21b43ecd21b44f }


condition:
	$a0
}