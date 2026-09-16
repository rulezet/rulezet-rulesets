rule Win_Trojan_Trivial_170
{
strings:
	$a0 = { b44eba1c01b120cd2186f0b43db29ecd2193b440ba0001b122cd21c3 }


condition:
	$a0
}