rule Win_Trojan_Peed_97
{
strings:
	$a0 = { 6bc900e8250000005589e5ad83ee04c9c2080089daf7da01d009c07401c383042425c3f7d029 }


condition:
	$a0
}