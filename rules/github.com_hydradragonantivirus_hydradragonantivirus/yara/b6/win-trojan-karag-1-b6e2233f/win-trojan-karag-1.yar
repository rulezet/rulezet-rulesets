rule Win_Trojan_Karag_1
{
strings:
	$a0 = { 0eb307ac0ac07404cd10ebf7e4603c4575fab80102b90200ba8000bb0080cd1372feb80103b9 }


condition:
	$a0
}