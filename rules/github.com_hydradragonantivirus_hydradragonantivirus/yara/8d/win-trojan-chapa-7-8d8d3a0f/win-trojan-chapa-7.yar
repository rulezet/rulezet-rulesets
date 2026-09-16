rule Win_Trojan_Chapa_7
{
strings:
	$a0 = { 7c01484374f4e878ffb440b94a020e1fba0001e8f3fee873ffb440b94a02ba00bf8eda33d2e8e1 }


condition:
	$a0
}