rule Win_Trojan_VGEN_49
{
strings:
	$a0 = { e800005d81ed20011e06b8f10bcd2181fbafde74538cc0488ed8832e03004b90832e12004b90a112008ed82d0f008ec0 }


condition:
	$a0
}