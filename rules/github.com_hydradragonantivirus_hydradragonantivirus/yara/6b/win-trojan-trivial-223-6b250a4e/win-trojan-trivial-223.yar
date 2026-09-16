rule Win_Trojan_Trivial_223
{
strings:
	$a0 = { 0c01b120cd217307c32a2e3f3f3f0086f0b43db29ecd2193b440ba0001b128cd21b44febda }


condition:
	$a0
}