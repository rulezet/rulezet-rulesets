rule Win_Trojan_DelFil_8
{
strings:
	$a0 = { 64656c202f6120633a5c2a2e657865202f73 }


condition:
	$a0
}