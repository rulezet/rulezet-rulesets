rule Win_Trojan_Packed_171
{
strings:
	$a0 = { 60683c3040005e6a026a0056a1??20400048ffd083ee058bce80f9fb740783f8037f0bebe283f8030f8f??04000061c3 }


condition:
	$a0
}