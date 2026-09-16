rule Win_Trojan_Trivial_372
{
strings:
	$a0 = { b80057cd215152b440ba0001b95500cd21b801575a59cd21b43ecd21b80143ba9e0059cd21b44f }


condition:
	$a0
}