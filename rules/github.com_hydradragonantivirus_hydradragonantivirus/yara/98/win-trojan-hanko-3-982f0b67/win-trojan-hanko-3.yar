rule Win_Trojan_Hanko_3
{
strings:
	$a0 = { 33f666bb4820d2a3662e019a27016681eb6f6b6e6183c60481 }


condition:
	$a0
}