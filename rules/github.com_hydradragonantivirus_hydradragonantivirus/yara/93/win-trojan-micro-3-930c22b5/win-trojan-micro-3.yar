rule Win_Trojan_Micro_3
{
strings:
	$a0 = { 010000c706d9010800c606db0102b904 }


condition:
	$a0
}