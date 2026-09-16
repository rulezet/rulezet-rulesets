rule Win_Trojan_Peed_282
{
strings:
	$a0 = { e8030000000f0108c1e15f83c40283c4027b0068fc7600005981c1305f000081c1fc }


condition:
	$a0
}