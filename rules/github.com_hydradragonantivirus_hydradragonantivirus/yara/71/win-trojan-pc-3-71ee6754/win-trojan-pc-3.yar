rule Win_Trojan_PC_3
{
strings:
	$a0 = { 1fbb0001803fe9753743803f15753143803f05752bb800 }


condition:
	$a0
}