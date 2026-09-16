rule Win_Trojan_VengG_1
{
strings:
	$a0 = { fc8bf283c63dbf0001b90300f3a48bf2b80fffcd21 }


condition:
	$a0
}