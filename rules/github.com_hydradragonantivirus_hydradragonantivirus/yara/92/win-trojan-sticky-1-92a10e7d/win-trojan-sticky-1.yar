rule Win_Trojan_Sticky_1
{
strings:
	$a0 = { 5d8bf556b98a03b300432e301c46e2f9c3 }


condition:
	$a0
}