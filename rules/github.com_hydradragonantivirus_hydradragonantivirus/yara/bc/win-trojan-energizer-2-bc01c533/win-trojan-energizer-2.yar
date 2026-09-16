rule Win_Trojan_Energizer_2
{
strings:
	$a0 = { 4033d2b9c202e8dbfe587218fcbfbe02abb026aab000e89900b440babd02b90400e8c0fee9b4fe }


condition:
	$a0
}