rule Win_Trojan_F_30
{
strings:
	$a0 = { e800008bfc368b2d81ed03012e803e6201b9745cb94c048dbe6201ba0100 }


condition:
	$a0
}