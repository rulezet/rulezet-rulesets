rule Win_Trojan_DelTree_5
{
strings:
	$a0 = { 64656c747265652f7920633a20 }


condition:
	$a0
}