rule Win_Trojan_TwelveTricksTrojan_1
{
strings:
	$a0 = { 0231944201d1c24e79f77b747df919 }


condition:
	$a0
}