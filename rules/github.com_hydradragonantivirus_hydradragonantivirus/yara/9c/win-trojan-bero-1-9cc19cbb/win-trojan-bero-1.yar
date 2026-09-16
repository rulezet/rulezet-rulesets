rule Win_Trojan_Bero_1
{
strings:
	$a0 = { e80000cc5d81ed03001e060e0e071f3e80be27000074248db63b008bfeb90d073e8a962700eb01 }


condition:
	$a0
}