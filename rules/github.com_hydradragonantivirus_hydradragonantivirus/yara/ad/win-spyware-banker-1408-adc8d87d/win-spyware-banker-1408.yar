rule Win_Spyware_Banker_1408
{
strings:
	$a0 = { bb25d678aff2ce781acd3ab485950f447cb2b0bdac896887e5567695d35c04d3815d66f71666a74f3bc238422bb9aba9a8c34220f2e3fa2d5098c5b5240d43eb4eb2fdc6 }


condition:
	$a0
}