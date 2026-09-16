rule Win_Trojan_Trivial_525
{
strings:
	$a0 = { ba1801cd21b43cba9e00cd21b74093ba0001b11ccd212a2e2a }


condition:
	$a0
}