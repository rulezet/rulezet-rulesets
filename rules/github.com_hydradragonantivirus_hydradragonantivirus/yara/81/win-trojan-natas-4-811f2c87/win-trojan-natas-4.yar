rule Win_Trojan_Natas_4
{
strings:
	$a0 = { 8d2e8ee73bd1904581c501004bd1c1f9f587f08bc2198ef82c81cb00007de7 }


condition:
	$a0
}