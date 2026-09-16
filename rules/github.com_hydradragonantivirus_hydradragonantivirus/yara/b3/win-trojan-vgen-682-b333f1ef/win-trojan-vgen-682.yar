rule Win_Trojan_VGEN_682
{
strings:
	$a0 = { ed03018db680018bfeadfec480fc3a7504fec0b430ab8db600018dbe8b07b98b0690ba000155e855005d51b43c8d }


condition:
	$a0
}