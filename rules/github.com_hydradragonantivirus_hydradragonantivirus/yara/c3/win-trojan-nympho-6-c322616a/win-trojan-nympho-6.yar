rule Win_Trojan_Nympho_6
{
strings:
	$a0 = { f3a58ed9fac7068400d2018c068600fb071fb84d5a }


condition:
	$a0
}