rule Win_Trojan_Fire_2
{
strings:
	$a0 = { feb80242e90300b8004233c933d2e8e0fec3b440e8dafec3b9550303c151b135f6f159b0352a }


condition:
	$a0
}