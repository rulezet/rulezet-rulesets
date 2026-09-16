rule Win_Trojan_Waledac_13
{
strings:
	$a0 = { 558bec83ec688b0528b042008d1d912b4e0003c3 }


condition:
	$a0
}