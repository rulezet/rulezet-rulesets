rule Win_Trojan_DelTree_12
{
strings:
	$a0 = { 64656c74726565202f7920633a5c77696e646f77730d }


condition:
	$a0
}