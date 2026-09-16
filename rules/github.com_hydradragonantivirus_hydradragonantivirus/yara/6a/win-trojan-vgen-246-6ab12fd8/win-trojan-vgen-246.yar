rule Win_Trojan_VGEN_246
{
strings:
	$a0 = { 21a25c09b430cd213c02740e77178d165d09b409cd21b44ccd218d169009b409cd21eb6090a12c008ec033ffb9 }


condition:
	$a0
}