rule Win_Trojan_GreenMonster_2
{
strings:
	$a0 = { c80514008ed8b9300390bb260180374d434975f9 }


condition:
	$a0
}