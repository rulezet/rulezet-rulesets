rule Win_Trojan_SillyRC_24
{
strings:
	$a0 = { c8488ed88b1e030083eb1490b44acd21bb1300b448cd210e1f2d10008ec0bf00018bf70e57b92801f3a406683001cb }


condition:
	$a0
}