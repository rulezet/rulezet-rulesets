rule Win_Trojan_DelTree_7
{
strings:
	$a0 = { 64656c74726565202f7920633a5c20 }


condition:
	$a0
}