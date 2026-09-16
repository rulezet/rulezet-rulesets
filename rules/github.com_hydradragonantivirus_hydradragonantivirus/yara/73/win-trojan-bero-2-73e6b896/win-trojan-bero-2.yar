rule Win_Trojan_Bero_2
{
strings:
	$a0 = { e80000cc5d81ed03001e060e0e071f3e80be28000074258db63c008bfeb913073e8a962800eb0290 }


condition:
	$a0
}