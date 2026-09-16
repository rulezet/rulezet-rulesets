rule Win_Trojan_Noone_2
{
strings:
	$a0 = { be????81fe????7509818442fb1600eb01908034??46e9eaff }


condition:
	$a0
}