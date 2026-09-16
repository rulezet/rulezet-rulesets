rule Win_Trojan_Yanshort_2
{
strings:
	$a0 = { 2f078cd80e1fbe370881ee030103f38904be390881ee030103f38cc089040e0753b8002fcd218bcb5bbed90b81ee030103f3890c83c6028cc089040e07bf5d }


condition:
	$a0
}