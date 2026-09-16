rule Win_Trojan_FrereJacqu_1
{
strings:
	$a0 = { 0619000e1fba5b02b82125cd218e0631 }


condition:
	$a0
}