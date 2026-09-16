rule Win_Trojan_Gen_132
{
strings:
	$a0 = { 8ec08ed8803e00005a741503060300 }


condition:
	$a0
}