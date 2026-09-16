rule Win_Trojan_R_46
{
strings:
	$a0 = { 8db62001b9bb01803400464975f9c3 }


condition:
	$a0
}