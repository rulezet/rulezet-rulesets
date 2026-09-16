rule Win_Trojan_Noone_3
{
strings:
	$a0 = { bb????81fb????7509818742fb1600eb01908007??43e9eaff }


condition:
	$a0
}