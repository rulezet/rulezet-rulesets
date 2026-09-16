rule Win_Spyware_Banker_2406
{
strings:
	$a0 = { 25ace734579cb708d88b10c4ccc080f4760dd2606ce6a1d3d129a7d1c61a233e07af948428e50fc027b2e5cec298c0d702c717df854e6cd72228d2c46dbcdfdd9c257e58320e1b486fb9 }


condition:
	$a0
}