rule Win_Trojan_BladeRunner_1
{
strings:
	$a0 = { 0300cd20005059ba01fab8455992cd1092929292929292bb2900bfa6012e8107 }


condition:
	$a0
}