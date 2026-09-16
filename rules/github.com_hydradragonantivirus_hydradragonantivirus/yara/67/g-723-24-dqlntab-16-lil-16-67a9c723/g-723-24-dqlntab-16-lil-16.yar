rule G_723_24__dqlntab__16_lil_16_
{
strings:
	$a0 = { 00F887001101750175011101870000F8 }

condition:
	$a0
}