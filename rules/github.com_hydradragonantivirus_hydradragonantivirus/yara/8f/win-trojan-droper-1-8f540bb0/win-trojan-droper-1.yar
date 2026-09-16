rule Win_Trojan_Droper_1
{
strings:
	$a0 = { 6a0553538d4c244c51686861400053ff15f4604000 }


condition:
	$a0
}