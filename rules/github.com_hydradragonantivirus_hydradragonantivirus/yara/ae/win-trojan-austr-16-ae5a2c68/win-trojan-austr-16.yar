rule Win_Trojan_Austr_16
{
strings:
	$a0 = { b9380fba0001cd21b8004233d233c9cd21b440b90400ba0001cd21595a }


condition:
	$a0
}