rule Win_Trojan_Slost_1
{
strings:
	$a0 = { ee0389b43c02bf0001568db43602b90300fcf3a45ee8d9018cc88ed80500108ec0b900015633f633fff3a45e0633 }


condition:
	$a0
}