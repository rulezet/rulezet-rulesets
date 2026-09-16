rule Win_Trojan_Meditation_3
{
strings:
	$a0 = { 425acd21721a2e8b0e0f01b4402bd2cd21b801572e8b16 }


condition:
	$a0
}