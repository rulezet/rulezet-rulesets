rule Win_Trojan_Gen_74
{
strings:
	$a0 = { 8b46f4a304008b46f6a306008b46eea308008b46f0a30a00 }


condition:
	$a0
}