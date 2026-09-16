rule Win_Trojan_ExeHd_3
{
strings:
	$a0 = { 4000cd276026813f4d5a7520268b4f1883f9407517535f03f926035dfc26813f504575081e }


condition:
	$a0
}