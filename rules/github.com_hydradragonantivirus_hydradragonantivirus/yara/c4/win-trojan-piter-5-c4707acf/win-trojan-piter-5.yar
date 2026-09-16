rule Win_Trojan_Piter_5
{
strings:
	$a0 = { 8e1e2c0033f6ac0a0475fb83c6038bd6bb3701 }


condition:
	$a0
}