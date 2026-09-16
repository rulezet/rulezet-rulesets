rule Win_Trojan_Vundo_37
{
strings:
	$a0 = { 60e8b31c0000ec2348 }


condition:
	$a0
}