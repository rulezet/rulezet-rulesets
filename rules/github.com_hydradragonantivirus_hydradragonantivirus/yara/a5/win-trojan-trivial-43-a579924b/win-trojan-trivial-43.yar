rule Win_Trojan_Trivial_43
{
strings:
	$a0 = { 6900b440cd21b43ecd21ba0001b44fcd213c187428ba9e00bf9e00b000b90c00f2aec60500b43d }


condition:
	$a0
}