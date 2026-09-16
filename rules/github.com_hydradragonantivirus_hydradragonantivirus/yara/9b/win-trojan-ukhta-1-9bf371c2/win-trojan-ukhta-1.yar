rule Win_Trojan_Ukhta_1
{
strings:
	$a0 = { c0fe7333968bd581ea8900b440b93f01cd217223b8004233c933d2cd2187fd81c7a00083ee032e }


condition:
	$a0
}