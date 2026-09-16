rule Win_Trojan_7thSon_1
{
strings:
	$a0 = { 8b0103f5bf0001a5a5b80033cd2152 }


condition:
	$a0
}