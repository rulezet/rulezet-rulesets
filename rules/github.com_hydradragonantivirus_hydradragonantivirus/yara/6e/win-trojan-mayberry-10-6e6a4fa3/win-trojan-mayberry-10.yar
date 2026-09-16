rule Win_Trojan_Mayberry_10
{
strings:
	$a0 = { cd21726e93b80057cd215152b43fb91c008d96b203 }


condition:
	$a0
}