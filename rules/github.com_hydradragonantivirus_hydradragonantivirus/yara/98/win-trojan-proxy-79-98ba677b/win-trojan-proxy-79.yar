rule Win_Trojan_Proxy_79
{
strings:
	$a0 = { d7bdedabb8e4b302595860b93bdba5de2bc72bce33c68bf90ffdc781df1fc9edab8b15d82e4100be420674ea81c0732ce323 }


condition:
	$a0
}