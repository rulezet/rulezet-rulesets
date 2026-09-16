rule Win_Trojan_Vgen_114
{
strings:
	$a0 = { 909090e800005d81ed07018d9e1e02ff374343ff37b41a8d962202cd21ccb44e8d961402cd217203eb0490e9b200b4 }


condition:
	$a0
}