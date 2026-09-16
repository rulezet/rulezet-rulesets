rule Win_Trojan_Trivial_184
{
strings:
	$a0 = { b44eba2001b92400cd21ba9e00b8023dcd2193ba0001b440cd21b43ecd21 }


condition:
	$a0
}