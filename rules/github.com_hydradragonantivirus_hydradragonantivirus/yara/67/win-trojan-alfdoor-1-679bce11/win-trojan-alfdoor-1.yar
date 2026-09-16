rule Win_Trojan_Alfdoor_1
{
strings:
	$a0 = { 5c52756e00000025735c58646963742e657865 }

	$a1 = { 61006c00660077006f006c0066 }


condition:
	$a0 and $a1
}