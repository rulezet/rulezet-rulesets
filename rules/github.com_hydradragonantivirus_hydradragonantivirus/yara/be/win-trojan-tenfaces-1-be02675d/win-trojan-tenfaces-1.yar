rule Win_Trojan_TenFaces_1
{
strings:
	$a0 = { 01040055fb01000100ffff6a0c0000450d0000030000006a0c }


condition:
	$a0
}