rule Win_Trojan_AppChild_1
{
strings:
	$a0 = { 4c6f6164f710412bd122e50ded164dbc0c50726fb4640e73730faac458ec457869100c00b1634d }


condition:
	$a0
}