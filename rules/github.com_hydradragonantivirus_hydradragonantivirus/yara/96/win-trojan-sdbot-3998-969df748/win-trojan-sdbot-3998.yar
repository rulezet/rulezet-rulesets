rule Win_Trojan_SdBot_3998
{
strings:
	$a0 = { 74714d4c712d177e502fdc7f43382da78a2aae892eae8d46aa17f4541b449aa994621a62d647e67f927e0ae89f8bfe2da37f4be8df02fa3787fecd40fba73c71dc3be5c9 }


condition:
	$a0
}