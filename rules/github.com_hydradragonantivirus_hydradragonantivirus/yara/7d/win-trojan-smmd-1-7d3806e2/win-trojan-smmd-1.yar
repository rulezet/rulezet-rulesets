rule Win_Trojan_Smmd_1
{
strings:
	$a0 = { 010100550001000000ffff18030000bd080000030000000103 }


condition:
	$a0
}