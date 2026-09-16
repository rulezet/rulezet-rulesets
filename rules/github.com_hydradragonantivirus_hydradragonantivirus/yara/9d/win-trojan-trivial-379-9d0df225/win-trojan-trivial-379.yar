rule Win_Trojan_Trivial_379
{
strings:
	$a0 = { fafafafafafafafab44eba3401cd21b8013dba9e00cd2193ba0001b15cb440cd21b43ecd21b44fcd2173e4b409ba3901 }


condition:
	$a0
}