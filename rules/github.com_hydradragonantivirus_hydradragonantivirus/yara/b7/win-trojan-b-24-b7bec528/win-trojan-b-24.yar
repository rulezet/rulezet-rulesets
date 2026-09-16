rule Win_Trojan_B_24
{
strings:
	$a0 = { be007c33c08ec0fa8ed08be6fb8ed8ff0e1304cd12b106d3e08ec033ffb90002fcf3a4a14c0026a3 }


condition:
	$a0
}