rule Win_Trojan_Gotcha_9
{
strings:
	$a0 = { 7103f3a4ba4101061fb82125cd2107 }


condition:
	$a0
}