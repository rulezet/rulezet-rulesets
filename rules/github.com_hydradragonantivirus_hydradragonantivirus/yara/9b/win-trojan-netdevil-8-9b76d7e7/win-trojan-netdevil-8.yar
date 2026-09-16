rule Win_Trojan_NetDevil_8
{
strings:
	$a0 = { 73747279206b6579206e616d652e000000558bec81c4a8faffff53565733db899da8faffff8bd98955fc8b45fce81b26fbff8dbdacfeffff33c05568e017450064 }


condition:
	$a0
}