rule Win_Trojan_VS_14
{
strings:
	$a0 = { 5053515256571e068cc88ed82b069000a3900033c08ed8803e12044b7503eb5990b44abbffffcd2183eb64b44acd21 }


condition:
	$a0
}