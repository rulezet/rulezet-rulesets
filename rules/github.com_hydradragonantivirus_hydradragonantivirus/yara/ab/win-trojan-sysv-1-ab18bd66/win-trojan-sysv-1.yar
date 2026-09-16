rule Win_Trojan_SYSV_1
{
strings:
	$a0 = { 40b912008d961802cd21b440b9f1018d961200cd21b801575a59cd21b43ecd21b80143595acd21 }


condition:
	$a0
}