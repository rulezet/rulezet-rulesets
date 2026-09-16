rule Win_Spyware_412_2
{
strings:
	$a0 = { 4252edf19bce0c47b3552772013bd671e045bee83d1fed97a98fea1d2faa22139be4cf7e0c537aef19aa7c9219f55169d6a56a7bf5ce8b78a7d773ee9bf7c3f2140ef5e280ed630b9d606a8f0c7f }


condition:
	$a0
}