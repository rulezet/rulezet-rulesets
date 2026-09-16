rule Win_Trojan_F_29
{
strings:
	$a0 = { 8bfc368b2d81ed03012e803e2d01b97427b993038dbe2d01ba0100 }


condition:
	$a0
}