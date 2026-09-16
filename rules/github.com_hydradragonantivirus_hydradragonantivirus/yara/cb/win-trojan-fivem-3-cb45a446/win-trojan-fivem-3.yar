rule Win_Trojan_Fivem_3
{
strings:
	$a0 = { 0e1f0e07e800008bfc368b2d81ed????444450558becc74602????5d58cd213dffff751d }


condition:
	$a0
}