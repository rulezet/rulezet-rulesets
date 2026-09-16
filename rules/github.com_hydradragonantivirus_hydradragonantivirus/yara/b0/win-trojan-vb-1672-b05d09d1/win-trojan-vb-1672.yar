rule Win_Trojan_VB_1672
{
strings:
	$a0 = { 33394341337d436f6e74726163746976656c79004f43d1d4e4fb5b3bae4794824b }


condition:
	$a0
}