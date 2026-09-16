rule Win_Trojan_Carnage_1
{
strings:
	$a0 = { e8050502002ea3b5022ec706b3029f00b440b99f02ba1000cd21b8004233c999cd21b440b91a00 }


condition:
	$a0
}