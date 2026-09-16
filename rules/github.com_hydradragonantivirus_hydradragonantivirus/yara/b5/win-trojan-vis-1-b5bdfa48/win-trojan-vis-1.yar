rule Win_Trojan_Vis_1
{
strings:
	$a0 = { ee0356b82135cd2126807f15cf74450e8c848700899c850007b449cd21b80358bb0100cd21b80158bb8200cd21b4 }


condition:
	$a0
}