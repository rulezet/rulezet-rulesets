rule Win_Trojan_Wolfman_5
{
strings:
	$a0 = { be040026837cfc00740446ebf6ea }


condition:
	$a0
}