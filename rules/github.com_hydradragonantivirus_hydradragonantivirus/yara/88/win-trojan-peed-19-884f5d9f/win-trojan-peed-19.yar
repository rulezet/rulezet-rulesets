rule Win_Trojan_Peed_19
{
strings:
	$a0 = { 1020b962adc4bb57c7db07620ab535adab5306690f60a306a5c97c90d23cb470 }


condition:
	$a0
}