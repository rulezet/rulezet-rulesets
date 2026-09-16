rule Win_Trojan_Trebujena_1
{
strings:
	$a0 = { 040e1fba00012e8b1e2a01b440cd21c333c050072ea1230126a390002ea1250126a39200c3 }


condition:
	$a0
}