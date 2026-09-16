rule Win_Trojan_Vgen_91
{
strings:
	$a0 = { 8916d602b430cd218b2e02008b1e2c008edaa339238c063723891e3323892e5323c7063d23ffffe81301c43e31 }


condition:
	$a0
}