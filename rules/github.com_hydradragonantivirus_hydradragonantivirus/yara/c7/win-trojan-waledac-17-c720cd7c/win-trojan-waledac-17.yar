rule Win_Trojan_Waledac_17
{
strings:
	$a0 = { 558bec83ec748b059fa54c008d15b5 }


condition:
	$a0
}