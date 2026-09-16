rule Win_Trojan_Sirius_1
{
strings:
	$a0 = { 60bb????b9a700300f43e2fb }


condition:
	$a0
}