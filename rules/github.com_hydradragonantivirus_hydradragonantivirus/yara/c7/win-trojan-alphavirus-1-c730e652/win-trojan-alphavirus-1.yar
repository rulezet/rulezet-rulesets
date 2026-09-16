rule Win_Trojan_AlphaVirus_1
{
strings:
	$a0 = { c08ec08cc88ed80575009026c70604003e0026a306008ec0be3e00bf3e00b9390090f3a49c580d0001500e6877 }


condition:
	$a0
}