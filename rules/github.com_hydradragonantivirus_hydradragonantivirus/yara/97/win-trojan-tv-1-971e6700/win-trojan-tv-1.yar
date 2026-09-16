rule Win_Trojan_TV_1
{
strings:
	$a0 = { 1e0e1fb42acd2180fe05750b3806d0227505c606cb00168cc0a3d000a3d400a3d8000510000106e0000106dc0050b8 }


condition:
	$a0
}