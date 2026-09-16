rule Win_Trojan_I13_8
{
strings:
	$a0 = { 39c68f8fdfed7815a1f45f86a15ca257dfedafc65f8622f4a1f4b538395f86a939c658a2b9a273a2 }


condition:
	$a0
}