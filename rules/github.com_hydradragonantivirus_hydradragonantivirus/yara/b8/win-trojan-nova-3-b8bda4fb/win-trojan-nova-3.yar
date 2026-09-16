rule Win_Trojan_Nova_3
{
strings:
	$a0 = { fa33db8edb8ed38be6fb5356b370c6474ffffc8b47dc898402008b47de89840400ff8fa303cd12c1e0068ec050 }


condition:
	$a0
}