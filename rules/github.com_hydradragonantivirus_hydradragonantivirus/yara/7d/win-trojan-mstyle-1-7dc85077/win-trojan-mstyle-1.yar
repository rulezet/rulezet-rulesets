rule Win_Trojan_Mstyle_1
{
strings:
	$a0 = { 0a0435ee687548b2c183b88d635f365131abd4a2fbddb8d600fefa0c4d5a }


condition:
	$a0
}