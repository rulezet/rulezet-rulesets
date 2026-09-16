rule Boucher_randgen5__32_lil_AND_
{
strings:
	$a0 = { 5d010000[0-20]b9030000[0-20]59020000[0-20]ef020000[0-20]2d020000[0-20]77030000 }

condition:
	$a0
}