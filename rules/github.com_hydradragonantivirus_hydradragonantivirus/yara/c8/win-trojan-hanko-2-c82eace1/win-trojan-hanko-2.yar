rule Win_Trojan_Hanko_2
{
strings:
	$a0 = { 33f666bb4820252f662e019a27016681eb706b6e6183c60481 }


condition:
	$a0
}