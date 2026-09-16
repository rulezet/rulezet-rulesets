rule Win_Trojan_Ascii_201_24_82_11_1
{
strings:
	$a0 = { 3230312e32342e38322e3131 }


condition:
	$a0
}