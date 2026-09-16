rule Win_Trojan_Small_4418
{
strings:
	$a0 = { 68??2e42000f6e04240f7ec0bacae8ff005250e8 }


condition:
	$a0
}