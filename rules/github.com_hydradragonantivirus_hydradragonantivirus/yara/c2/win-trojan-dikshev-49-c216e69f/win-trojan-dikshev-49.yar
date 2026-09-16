rule Win_Trojan_Dikshev_49
{
strings:
	$a0 = { 50b82a2e508bd4b44eb9ffffcd21721eb8023d33d2b29ecd2193b4402bd2fec633c9b135cd21 }


condition:
	$a0
}