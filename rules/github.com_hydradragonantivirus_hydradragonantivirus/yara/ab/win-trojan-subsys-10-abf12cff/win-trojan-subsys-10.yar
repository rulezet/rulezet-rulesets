rule Win_Trojan_Subsys_10
{
strings:
	$a0 = { 9510ed2619f6695ba0a139fbfa66ce0632a85e3be86f133473d202cf93c5f74f4705a85f7b018c884a90f20c3fbd49cbbcfffa841de896c658077be1c31ff990 }


condition:
	$a0
}