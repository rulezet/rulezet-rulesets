rule Win_Trojan_Opa_8
{
strings:
	$a0 = { 1d018bd8b4401e0e1fba0001b95a009c2eff1e1d011fcf }


condition:
	$a0
}