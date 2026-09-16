rule Win_Trojan_Voronezh_5
{
strings:
	$a0 = { c9b800425b53cd218b0e58078d164007b440cd21 }


condition:
	$a0
}