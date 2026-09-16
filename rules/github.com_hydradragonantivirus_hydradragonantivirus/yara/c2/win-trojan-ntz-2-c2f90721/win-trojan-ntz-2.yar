rule Win_Trojan_NTZ_2
{
strings:
	$a0 = { cd21888e2301b9de008db66f018dbe3502a48a86350232862301888635028d7cff8db63502a4 }


condition:
	$a0
}