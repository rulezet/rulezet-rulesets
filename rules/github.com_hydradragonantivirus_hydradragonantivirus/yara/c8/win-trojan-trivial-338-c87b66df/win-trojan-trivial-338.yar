rule Win_Trojan_Trivial_338
{
strings:
	$a0 = { cd2193b440b142ba0001cd21b43ecd21 }


condition:
	$a0
}