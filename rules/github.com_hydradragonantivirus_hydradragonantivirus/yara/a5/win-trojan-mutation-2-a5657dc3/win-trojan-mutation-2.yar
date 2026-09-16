rule Win_Trojan_Mutation_2
{
strings:
	$a0 = { c30299076334e834f3ca00a64f01240720a4c9029547980021bdc602ec2699056334e834f3ca0054 }


condition:
	$a0
}