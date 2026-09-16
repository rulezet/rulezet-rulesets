rule Win_Trojan_Praying_1
{
strings:
	$a0 = { 4b74052eff2e0d009c50535152565755061e2e891611 }


condition:
	$a0
}