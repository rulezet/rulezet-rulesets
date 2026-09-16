rule Win_Trojan_Mini_2
{
strings:
	$a0 = { 5a33c95149cd210564005950b8004299cd21b44059565acd210e1fb43ecd21b44febb52a2e }


condition:
	$a0
}