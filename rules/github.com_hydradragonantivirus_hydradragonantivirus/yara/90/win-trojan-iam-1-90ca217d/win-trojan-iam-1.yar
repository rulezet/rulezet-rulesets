rule Win_Trojan_IAM_1
{
strings:
	$a0 = { 408b1ebd02ba0001b95b00cd21a10001b92002bb5b01f72661038a1732d08897600243e2f133c9 }


condition:
	$a0
}