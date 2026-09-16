rule Win_Trojan_FormatC_11
{
strings:
	$a0 = { 6563686f20597c666f726d617420633a????6563686f20536869747c4c6162656c2043 }


condition:
	$a0
}