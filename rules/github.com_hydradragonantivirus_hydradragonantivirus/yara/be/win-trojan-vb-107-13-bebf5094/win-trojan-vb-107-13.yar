rule Win_Trojan_VB_107_13
{
strings:
	$a0 = { 851f44a27b0fa3e8182aaa13fb20ffff87004f506c7567696e5f4d6f7573654675 }


condition:
	$a0
}