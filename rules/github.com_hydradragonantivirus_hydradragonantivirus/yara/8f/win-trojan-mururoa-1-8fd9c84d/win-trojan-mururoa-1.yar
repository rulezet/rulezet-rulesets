rule Win_Trojan_Mururoa_1
{
strings:
	$a0 = { 05eb1d5eeb1c2e3014eb12b92500eb072e8a944a09ebf4 }


condition:
	$a0
}