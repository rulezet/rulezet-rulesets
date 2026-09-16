rule Win_Trojan_Trivial_73
{
strings:
	$a0 = { ba100133c9cd21b43cba9e00cd212a2e2a0087d1b74093cd21b44febe3 }


condition:
	$a0
}