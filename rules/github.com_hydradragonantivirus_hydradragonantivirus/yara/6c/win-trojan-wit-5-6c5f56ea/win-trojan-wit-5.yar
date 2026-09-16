rule Win_Trojan_Wit_5
{
strings:
	$a0 = { 06ba0001b92a0290cd218a660ab00233c933d2cd218b16f20281c296008bf28b0ea202e83200 }


condition:
	$a0
}