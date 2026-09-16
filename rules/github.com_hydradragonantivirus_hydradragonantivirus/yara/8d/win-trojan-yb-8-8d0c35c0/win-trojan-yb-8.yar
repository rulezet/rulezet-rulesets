rule Win_Trojan_YB_8
{
strings:
	$a0 = { 3dcd2193b905008d947501b43fcd2172218b84980105 }


condition:
	$a0
}