rule Win_Trojan_VGEN_609
{
strings:
	$a0 = { 4f4b49fc1eb800bd8ec033ff0e1fe800005e83ee13b9c00190f3a4ea4c0000bd3d004b751d50531e5206b4bd8ec0 }


condition:
	$a0
}