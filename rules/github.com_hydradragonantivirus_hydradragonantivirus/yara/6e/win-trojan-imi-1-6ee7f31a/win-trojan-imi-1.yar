rule Win_Trojan_Imi_1
{
strings:
	$a0 = { 89166503b430cd218b2e02008b1e2c008edaa3a94b8c06a74b891ea34b892ebf4be85a01c43ea14b8bc78bd8b9 }


condition:
	$a0
}