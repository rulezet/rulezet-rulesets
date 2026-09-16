rule Win_Trojan_Peed_246
{
strings:
	$a0 = { fcbd7273030087f47341ff1537647400e88147c3ff8f0537377600f7d3685359 }


condition:
	$a0
}