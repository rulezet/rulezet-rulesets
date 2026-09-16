rule Win_Trojan_Quiz_1
{
strings:
	$a0 = { 01b43fb5fdcd218bfa813d561e7427803d4d0f84c100 }


condition:
	$a0
}