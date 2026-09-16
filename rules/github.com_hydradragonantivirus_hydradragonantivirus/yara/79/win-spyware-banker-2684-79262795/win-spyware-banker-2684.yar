rule Win_Spyware_Banker_2684
{
strings:
	$a0 = { badfbd50cdaaa22350a90db6fde3c66ea2b31f21475f7ebe83224da313d470f953c2f9145cf56dd83abec91d64d1e44f2e4e3b56706ada0875a3f30ed5c7f8767524dc6b43f1d5c277116fb33b36 }


condition:
	$a0
}