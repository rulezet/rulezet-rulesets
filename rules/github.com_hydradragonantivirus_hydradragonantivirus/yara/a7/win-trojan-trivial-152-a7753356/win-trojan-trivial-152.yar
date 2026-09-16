rule Win_Trojan_Trivial_152
{
strings:
	$a0 = { b44eba1a01cd2186f0b29eb43dcd2193b440ba0001b120cd21c3 }


condition:
	$a0
}