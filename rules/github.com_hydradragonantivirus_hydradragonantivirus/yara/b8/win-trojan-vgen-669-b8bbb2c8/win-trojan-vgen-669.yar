rule Win_Trojan_VGEN_669
{
strings:
	$a0 = { 81ed03018db67e018bfeadfec480fc3a7504fec0b430ab8db600018dbe2d06b92d0590ba000155e853005d51b43c8d }


condition:
	$a0
}