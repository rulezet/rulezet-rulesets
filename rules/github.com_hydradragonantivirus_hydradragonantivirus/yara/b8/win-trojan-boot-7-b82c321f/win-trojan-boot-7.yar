rule Win_Trojan_Boot_7
{
strings:
	$a0 = { ba8000cd13721b813fe8187415b8010341cd138bf589dfb9a501f3a4b8010341cd13071f83 }


condition:
	$a0
}