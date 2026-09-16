rule Win_Trojan_Noone_1
{
strings:
	$a0 = { bf????81ff????7509818542fb1600eb01908035??47e9eaff }


condition:
	$a0
}