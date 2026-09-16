rule Boucher_randgen1__32_lil_AND_
{
strings:
	$a0 = { 6f010000[0-20]ab000000[0-20]77030000[0-20]50010000[0-20]d1050000[0-20]fc000000 }

condition:
	$a0
}