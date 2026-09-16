rule Win_Trojan_Leralogs_1
{
strings:
	$a0 = { 50726f6a656374204c657261204b65792e657865 }


condition:
	$a0
}