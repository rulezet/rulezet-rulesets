rule Win_Trojan_Violator_6
{
strings:
	$a0 = { e2edb405b500b6008a166403cd13 }


condition:
	$a0
}