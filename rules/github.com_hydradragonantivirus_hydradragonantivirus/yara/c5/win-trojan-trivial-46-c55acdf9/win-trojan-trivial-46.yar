rule Win_Trojan_Trivial_46
{
strings:
	$a0 = { ba000131c9b44ecd21ba9e00b000b90c00f2aec60500b001b43dcd2189c3ba0001b96900b440cd21b43ecd21ba0001b44fcd213c187428ba9e00 }


condition:
	$a0
}