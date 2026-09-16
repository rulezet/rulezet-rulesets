rule Win_Trojan_Anarkia_1
{
strings:
	$a0 = { 19000e1fba5c02b82125cd218e0631 }


condition:
	$a0
}