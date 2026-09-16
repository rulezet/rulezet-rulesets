rule Win_Trojan_Trivial_389
{
strings:
	$a0 = { ba2f01b44ecd213d12007414e83c008b1e4c01535bb99200ba0001b440cd21c3ba3501b43b }


condition:
	$a0
}