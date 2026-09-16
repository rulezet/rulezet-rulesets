rule Win_Trojan_Mordor_2
{
strings:
	$a0 = { 4559b801facd21b8da35cd2183fb01740fe973010000000080fc4b740ae93301e9c1005b5aebf65253525b83c3068a }


condition:
	$a0
}