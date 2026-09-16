rule Win_Trojan_Aniver_1
{
strings:
	$a0 = { 83c406585b595a5e5f5d1f07f9ca02005d81ed3001b42fcd21899e2b03b41a8d962d03cd21b824258d963001 }


condition:
	$a0
}