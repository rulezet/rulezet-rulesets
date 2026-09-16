rule Win_Trojan_Kotos_1
{
strings:
	$a0 = { 58488ec0268b1e030081eb1004b44a07cd21b448bb0002cd2106fc8ec0be01018b040503018bf0bf0301b96604f3 }


condition:
	$a0
}