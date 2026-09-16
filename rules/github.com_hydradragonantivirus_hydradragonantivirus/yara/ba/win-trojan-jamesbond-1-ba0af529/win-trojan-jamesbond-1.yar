rule Win_Trojan_JamesBond_1
{
strings:
	$a0 = { 5351521e06575680fc4b740c80fc3d74078bd780fc6c }


condition:
	$a0
}