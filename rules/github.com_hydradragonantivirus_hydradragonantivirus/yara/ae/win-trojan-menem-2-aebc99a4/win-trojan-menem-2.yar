rule Win_Trojan_Menem_2
{
strings:
	$a0 = { cd21891e381a8c063a1ab41aba0b1acd21a10f01a31101bb13018b073d4d5a7557b44eb90000baf819cd21724bbb }


condition:
	$a0
}