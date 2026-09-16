rule Win_Trojan_Viva_1
{
strings:
	$a0 = { 01258d9671033e2ecd2106b821353ecd21899e79038c867b0307b40232d2e82f02b208e82a02c6 }


condition:
	$a0
}