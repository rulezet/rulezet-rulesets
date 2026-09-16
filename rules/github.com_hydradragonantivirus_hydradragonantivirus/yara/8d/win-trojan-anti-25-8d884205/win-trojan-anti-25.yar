rule Win_Trojan_Anti_25
{
strings:
	$a0 = { 83c715b9a901f3a426c74705eb0e5e595f1fb801039c2eff1e09001e5751560e1fbe15008b }


condition:
	$a0
}