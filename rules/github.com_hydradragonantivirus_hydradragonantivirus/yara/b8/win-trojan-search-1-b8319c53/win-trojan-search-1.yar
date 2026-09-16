rule Win_Trojan_Search_1
{
strings:
	$a0 = { ee0c56bf0001b90300f3a4b44eb903005a5283c203cd21eb0790b44fcd21725eb8023dba9e00cd2193b43fb90300 }


condition:
	$a0
}