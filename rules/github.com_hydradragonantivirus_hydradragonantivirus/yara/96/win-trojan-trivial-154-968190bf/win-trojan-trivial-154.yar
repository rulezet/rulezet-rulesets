rule Win_Trojan_Trivial_154
{
strings:
	$a0 = { b44eba1a01cd21ba9e00b8023dcd2193b440ba0001b120cd21c3 }


condition:
	$a0
}