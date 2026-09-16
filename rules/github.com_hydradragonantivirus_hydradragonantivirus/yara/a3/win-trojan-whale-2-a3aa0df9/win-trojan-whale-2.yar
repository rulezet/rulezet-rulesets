rule Win_Trojan_Whale_2
{
strings:
	$a0 = { e802000e4f5a0e81eaa0231fb9d70b }


condition:
	$a0
}