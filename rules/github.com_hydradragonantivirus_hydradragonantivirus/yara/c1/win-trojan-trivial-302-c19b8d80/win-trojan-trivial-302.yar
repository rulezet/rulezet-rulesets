rule Win_Trojan_Trivial_302
{
strings:
	$a0 = { b44eba2701cd21721db43db002ba9e00cd219333d2fec6b440b93300cd21b43ecd21b44febdfc3 }


condition:
	$a0
}