rule Win_Trojan_Timid_9
{
strings:
	$a0 = { 0d813e5aff56497505b0010ac0c3 }


condition:
	$a0
}