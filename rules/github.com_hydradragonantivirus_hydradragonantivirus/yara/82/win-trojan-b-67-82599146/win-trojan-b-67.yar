rule Win_Trojan_B_67
{
strings:
	$a0 = { bcf0ff1eb8b90e50cb8816460e33c08e }


condition:
	$a0
}