rule Win_Trojan_AdiPop_1
{
strings:
	$a0 = { 7403e99e00b8c40dcd602e891e88012e8c068a0152 }


condition:
	$a0
}