rule Win_Trojan_VInfo_1
{
strings:
	$a0 = { 5b83eb032e807f775a7410bf0001be760003f357a5 }


condition:
	$a0
}