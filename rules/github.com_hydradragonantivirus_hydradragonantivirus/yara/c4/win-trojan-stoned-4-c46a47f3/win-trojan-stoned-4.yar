rule Win_Trojan_Stoned_4
{
strings:
	$a0 = { bf8001b98000f3a4b80103bb0002b90300b601f6c2807405b9070032f69c2eff1ef900720f }


condition:
	$a0
}