rule Win_Trojan_Peed_207
{
strings:
	$a0 = { eb5381e94432bb006800443e815a01c2528b0205 }


condition:
	$a0
}