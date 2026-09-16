rule Win_Trojan_Gotcha_11
{
strings:
	$a0 = { 03f3a4ba3f01061fb82125cd2107 }


condition:
	$a0
}