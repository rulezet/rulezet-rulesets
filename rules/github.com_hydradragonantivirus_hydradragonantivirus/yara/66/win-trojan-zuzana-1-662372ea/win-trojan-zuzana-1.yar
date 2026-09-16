rule Win_Trojan_Zuzana_1
{
strings:
	$a0 = { a31304b106d3e08ec0be007cb90002fcf3a4a14c0026a37b00a14e0026a37d00c7064c007f008c }


condition:
	$a0
}