rule Win_Trojan_Satan_3
{
strings:
	$a0 = { 909090e800005a83ea03525d8bf281c69c02bf0001b90500acaae2fcbe8200ac3c5b7503e91601b42acd2180fe0c }


condition:
	$a0
}