rule Win_Spyware_Banker_1302
{
strings:
	$a0 = { 14fd38f0cc747ad6c1077ce8fbd997bd484741f5503963e8bfb21c137871cfa77825d9099b06c02adc9dee5c17b544d898aa6d958d33aceb23f9f904572bfce6f401b1b3 }


condition:
	$a0
}