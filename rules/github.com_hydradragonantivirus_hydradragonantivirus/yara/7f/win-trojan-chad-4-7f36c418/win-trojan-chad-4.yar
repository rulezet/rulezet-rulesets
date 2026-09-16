rule Win_Trojan_Chad_4
{
strings:
	$a0 = { b440b9ef028b14cd21b8004233c933d2cd21b440b9 }


condition:
	$a0
}