rule Win_Trojan_Genius_1
{
strings:
	$a0 = { cd211fc3b81635cd21899ea1058c86a30581c36403813f45097504c7076d08c3 }


condition:
	$a0
}