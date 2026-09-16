rule Win_Trojan_N_38
{
strings:
	$a0 = { eb00e800005d81ed060150535152565755061eb8cd7bcd2181fbcd7b747f33db0e1f8cc1b80935cd212e8c86cc012e89 }


condition:
	$a0
}