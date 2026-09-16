rule Win_Trojan_IKV_1
{
strings:
	$a0 = { 8bdf2bd983c31783e92c301f43e2fb }


condition:
	$a0
}