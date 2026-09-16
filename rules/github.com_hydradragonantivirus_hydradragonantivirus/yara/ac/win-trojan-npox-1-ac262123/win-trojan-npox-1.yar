rule Win_Trojan_NPox_1
{
strings:
	$a0 = { 2acd2180fa0d7403eb2390b500b405b600b280cd13fec5 }


condition:
	$a0
}