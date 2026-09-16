rule Win_Trojan_Waledac_20
{
strings:
	$a0 = { 558bec83ec548b057a9f4b008d3d713841 }


condition:
	$a0
}