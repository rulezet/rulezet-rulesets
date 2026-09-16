rule Win_Trojan_GV_1
{
strings:
	$a0 = { 280cb90004cd2150e896ff58508bd0f7d242b9ffffb80142cd2159b440ba280ccd213d0004 }


condition:
	$a0
}