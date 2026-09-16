rule Win_Trojan_VCS_2
{
strings:
	$a0 = { b90f0489feac32c4aae2 }


condition:
	$a0
}