rule Win_Trojan_Cmapp_1
{
strings:
	$a0 = { 8bf0566844b3001089742424e83605000083c40c85c00f840e020000 }


condition:
	$a0
}