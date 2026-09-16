rule Win_Trojan_Mayberry_7
{
strings:
	$a0 = { 3dcd21723593b80057cd215152b43fb91c008d96f902 }


condition:
	$a0
}