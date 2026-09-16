rule Win_Spyware_Banker_2746
{
strings:
	$a0 = { ab7b97981b082f8ada16cdcbc0f0a6e8f0ac4c5a8edcaf9649676562df419d8900193f353b029f8950b3937fdb45171dfe9ccbac48b22acdf499c65aefb4723f1ff5f709888d4e1b03c0bd }


condition:
	$a0
}