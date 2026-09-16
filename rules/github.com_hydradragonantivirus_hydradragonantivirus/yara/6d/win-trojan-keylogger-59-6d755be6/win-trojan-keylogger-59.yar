rule Win_Trojan_Keylogger_59
{
strings:
	$a0 = { 558bec83ec2456578d7ddce8450000008b7d0881c704010000be44bc4600 }


condition:
	$a0
}