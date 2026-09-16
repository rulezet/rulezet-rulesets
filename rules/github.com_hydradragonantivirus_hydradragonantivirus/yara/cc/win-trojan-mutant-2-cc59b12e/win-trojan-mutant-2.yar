rule Win_Trojan_Mutant_2
{
strings:
	$a0 = { 90b9360385c533c7f9bbc2173bc29043438b1703c651b106d3c23733d5b102d3ca59378b2f33c78917f5ad0bc3 }


condition:
	$a0
}