rule Win_Trojan_VGEN_350
{
strings:
	$a0 = { e80f00002e8035aa8bec8b7e002e8035aacf5e9c1e069c33c08ed88bc640a304008c0e06008bec9c8076ff018bfe81c7 }


condition:
	$a0
}