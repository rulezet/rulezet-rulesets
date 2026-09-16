rule Win_Trojan_Small_3284
{
strings:
	$a0 = { 5d596f68687f746efbdffddb5e7305796e7568635b1a27ae829d94ab848188aced0bffdfff7fac8e9fa88486868a858fa782858eaaeb8f4b697858656f674f637fff76f77962780c0f4e50 }


condition:
	$a0
}