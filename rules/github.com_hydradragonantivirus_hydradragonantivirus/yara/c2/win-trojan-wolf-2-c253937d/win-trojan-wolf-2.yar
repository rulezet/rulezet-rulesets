rule Win_Trojan_Wolf_2
{
strings:
	$a0 = { b30053b003b90a00ba0100cd265bb40b32ffcd10fec380fb0775e7ebe33e8aa6b3042e882600 }


condition:
	$a0
}