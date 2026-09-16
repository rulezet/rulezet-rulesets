rule Win_Trojan_Eumel_4
{
strings:
	$a0 = { 7303e9a800b8023d31865e02ba82facd218bd8b80242e8a8003de9037c163dfff97c11b80057 }


condition:
	$a0
}