rule Win_Trojan_Yom_1
{
strings:
	$a0 = { b8004233c9cd2150b440b9e65fba0001cd2158c606cb604dc606cc60e8a3cd60b8004233c933 }


condition:
	$a0
}