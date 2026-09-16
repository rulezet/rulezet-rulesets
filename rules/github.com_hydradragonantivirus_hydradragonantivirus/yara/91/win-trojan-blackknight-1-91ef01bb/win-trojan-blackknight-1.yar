rule Win_Trojan_BlackKnight_1
{
strings:
	$a0 = { 8ed9be8400bf0803ba5b01ad3bc2740baba5061fb821 }


condition:
	$a0
}