rule Win_Trojan_Typo_3
{
strings:
	$a0 = { 02908bd681c20000cd2172328344031933d233c9b800 }


condition:
	$a0
}