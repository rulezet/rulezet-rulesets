rule Win_Trojan_Hupigon_1480
{
strings:
	$a0 = { 6052515050525350 }


condition:
	$a0
}