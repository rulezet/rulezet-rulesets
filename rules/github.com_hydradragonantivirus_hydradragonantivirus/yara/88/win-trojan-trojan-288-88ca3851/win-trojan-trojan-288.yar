rule Win_Trojan_Trojan_288
{
strings:
	$a0 = { 5c002e8916f801b430cd218b2e02008b1e2c008edaa392008c069000891e8c00892eac00c7069600ffffe83401c43e }


condition:
	$a0
}