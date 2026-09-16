rule Win_Trojan_YB_9
{
strings:
	$a0 = { cd2193b905008d947601b43fcd2172218b84990105 }


condition:
	$a0
}