rule Win_Trojan_Zbot_1263
{
strings:
	$a0 = { 88d16692b1708db1a6524d0164a1300000008d986a972cd7605b8b50100f9dc10f92c1548b40 }


condition:
	$a0
}