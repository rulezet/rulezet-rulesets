rule Win_Trojan_HarmWare_1
{
strings:
	$a0 = { 8ec49038f1f587dbf986edfc23fffaf584c3f988ed1efd87c0fd38d2f8750050fca89f9023c91ff821e4fa09f6 }


condition:
	$a0
}