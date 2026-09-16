rule Win_Trojan_MF_7
{
strings:
	$a0 = { 7e8016579a560595009a91029500bf4c2f1e57e873f989ec5dc3115b5241572d312c2044756b65 }


condition:
	$a0
}