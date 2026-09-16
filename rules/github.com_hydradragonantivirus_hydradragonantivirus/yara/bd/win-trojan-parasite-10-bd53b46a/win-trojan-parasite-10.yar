rule Win_Trojan_Parasite_10
{
strings:
	$a0 = { b80057cd215152b440b9a701ba0001cd21b8004233c933d2cd21b440b104ba1a01cd215a59 }


condition:
	$a0
}