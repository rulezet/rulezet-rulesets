rule Win_Trojan_DVCL_2
{
strings:
	$a0 = { 2e4558450000800000b7108bd3b41acd21b44acd21b44ebf1e108bd6cd2173268e062c0033ffb8 }


condition:
	$a0
}