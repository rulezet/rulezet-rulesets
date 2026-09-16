rule Win_Trojan_Trojan_266
{
strings:
	$a0 = { b6e643b0e7e642e642fc33c08ed8a11304484848a31304b106d3e0560e078dbcf401be5800fca5 }


condition:
	$a0
}