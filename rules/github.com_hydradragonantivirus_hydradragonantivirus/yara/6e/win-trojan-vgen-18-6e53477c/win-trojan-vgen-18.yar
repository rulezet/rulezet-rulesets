rule Win_Trojan_VGEN_18
{
strings:
	$a0 = { c6061a0100baf602b409cd21b430cd2186c43d0303723ab80f01cd2f3b060301742fb82f35cd21891e15018c061701ba }


condition:
	$a0
}