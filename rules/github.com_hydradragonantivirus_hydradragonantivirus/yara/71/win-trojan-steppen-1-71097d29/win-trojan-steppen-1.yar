rule Win_Trojan_Steppen_1
{
strings:
	$a0 = { 09002a2e636f6d002e2e00b801faba4559cd165d81ed1c018db6da01bf000157a5a4b41a8d962f }


condition:
	$a0
}