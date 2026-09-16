rule Win_Trojan_Sauron_1
{
strings:
	$a0 = { 86fbecc0bea3e5e9bff0255dc301203fc44feb0202bfaf020ecab2c51d34b8fffff13c0ae28fec }


condition:
	$a0
}