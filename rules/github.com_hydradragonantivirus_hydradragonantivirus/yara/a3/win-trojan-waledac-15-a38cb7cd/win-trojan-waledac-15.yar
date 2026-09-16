rule Win_Trojan_Waledac_15
{
strings:
	$a0 = { 558bec83ec648b05592c4d008d3d4e4b45 }


condition:
	$a0
}