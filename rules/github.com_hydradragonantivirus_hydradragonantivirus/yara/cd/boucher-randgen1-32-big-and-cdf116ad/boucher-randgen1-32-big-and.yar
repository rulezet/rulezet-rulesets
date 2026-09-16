rule Boucher_randgen1__32_big_AND_
{
strings:
	$a0 = { 0000016f[0-20]000000ab[0-20]00000377[0-20]00000150[0-20]000005d1[0-20]000000fc }

condition:
	$a0
}