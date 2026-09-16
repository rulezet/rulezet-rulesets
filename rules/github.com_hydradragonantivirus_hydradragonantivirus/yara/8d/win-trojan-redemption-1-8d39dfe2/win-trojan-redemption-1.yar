rule Win_Trojan_Redemption_1
{
strings:
	$a0 = { 3580bc410003c83bc173298d5430813bca7321813950450000c644241301750c81b9ab0100002f }


condition:
	$a0
}