rule Win_Trojan_WMAK5747_1
{
strings:
	$a0 = { 7c33fffa8ed78be6fb8edfc6061b7c02cd128be82d1400a31304b106d3e08ec0b9000251fcf3 }


condition:
	$a0
}