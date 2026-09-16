rule Win_Trojan_Trivial_383
{
strings:
	$a0 = { b44f33c9cd21721bebd08bd8b440b96100ba0001cd21b8015733c933d2cd21b43ecd21b44ccd21 }


condition:
	$a0
}