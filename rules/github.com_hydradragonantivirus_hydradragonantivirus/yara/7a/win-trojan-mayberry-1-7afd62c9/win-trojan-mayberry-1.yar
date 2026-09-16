rule Win_Trojan_Mayberry_1
{
strings:
	$a0 = { cd21726e93b80057cd215152b43fb91c008d969502 }


condition:
	$a0
}