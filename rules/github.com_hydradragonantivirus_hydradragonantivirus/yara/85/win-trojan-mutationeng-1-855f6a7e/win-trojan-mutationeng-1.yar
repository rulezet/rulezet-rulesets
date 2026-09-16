rule Win_Trojan_MutationEng_1
{
strings:
	$a0 = { 9090e800005ebf000183ee03501e065756fcb430 }


condition:
	$a0
}