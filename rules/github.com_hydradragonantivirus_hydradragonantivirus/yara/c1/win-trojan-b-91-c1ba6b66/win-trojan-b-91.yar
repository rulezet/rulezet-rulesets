rule Win_Trojan_B_91
{
strings:
	$a0 = { be03bfbe01b92101f3a5c6060a0001b8010333dbb90100cd13bebe04bfbe01 }


condition:
	$a0
}