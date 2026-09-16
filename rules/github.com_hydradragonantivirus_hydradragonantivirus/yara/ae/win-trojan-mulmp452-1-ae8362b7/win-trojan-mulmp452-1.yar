rule Win_Trojan_MULMP452_1
{
strings:
	$a0 = { beff7222803ffc741db80103b10550cd1358886e028db7be018dbebe01b121f3a5418bddcd13 }


condition:
	$a0
}