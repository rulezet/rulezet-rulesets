rule Win_Trojan_Phunnie_1
{
strings:
	$a0 = { 8b9c3502b90600baf30103d6cd21b442b0008b9c3502 }


condition:
	$a0
}