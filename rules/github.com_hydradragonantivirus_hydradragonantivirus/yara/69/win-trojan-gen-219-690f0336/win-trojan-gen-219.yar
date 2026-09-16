rule Win_Trojan_Gen_219
{
strings:
	$a0 = { 2cb4038a168b4e088a5611000a8a7606cd13b000730288e01d0800a01d48bbfa0fcd21a352 }


condition:
	$a0
}