rule Win_Trojan_Peed_280
{
strings:
	$a0 = { e802000000ff36c1e10f83c40183c4037b5751b9 }


condition:
	$a0
}