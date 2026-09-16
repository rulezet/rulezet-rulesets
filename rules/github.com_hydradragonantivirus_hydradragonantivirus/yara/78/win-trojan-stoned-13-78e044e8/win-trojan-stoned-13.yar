rule Win_Trojan_Stoned_13
{
strings:
	$a0 = { 0103bb0002b90600cd1372e58b363000bfbe01b92101f3a5c6060a0001b8010333dbb90100cd13 }


condition:
	$a0
}