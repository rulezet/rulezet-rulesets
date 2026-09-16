rule Win_Trojan_Dikshev_9
{
strings:
	$a0 = { 130e87d6b440b90300cce8d5078dbeaa0ee82001e8df07e8b6078d96aa0e8bcf2bcab440cc }


condition:
	$a0
}