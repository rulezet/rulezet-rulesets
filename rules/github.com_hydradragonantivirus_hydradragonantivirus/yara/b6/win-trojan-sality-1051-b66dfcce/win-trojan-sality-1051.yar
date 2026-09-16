rule Win_Trojan_Sality_1051
{
strings:
	$a0 = { 5f??8a440500300789dbfec989c05e4e0f85 }


condition:
	$a0
}