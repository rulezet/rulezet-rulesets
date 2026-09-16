rule Win_Trojan_Inch_2
{
strings:
	$a0 = { 0f807c04387509807c05337503eb4a905b53b002e88900 }


condition:
	$a0
}