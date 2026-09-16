rule Win_Trojan_Lineage_93
{
strings:
	$a0 = { 8313f55c371833b3eee95e187167942a9ddc3d907fcb12159e0be1353e01a32abbaa5b5edba15f349cd790015fc3c03372cb3ac9f847b785bcb6d5d1d7987fb9b7a1b76e }


condition:
	$a0
}