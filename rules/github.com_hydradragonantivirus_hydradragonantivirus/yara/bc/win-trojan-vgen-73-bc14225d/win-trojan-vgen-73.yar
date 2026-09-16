rule Win_Trojan_Vgen_73
{
strings:
	$a0 = { c08ed8b80000cd330bc07506bad605e99800be810033c9ac3c0a74653c0d74613c2074f3be6500c60451c64401 }


condition:
	$a0
}