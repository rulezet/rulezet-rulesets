rule Win_Spyware_Lineage_31
{
strings:
	$a0 = { e2ecadae53f9a0b1341c86cf0292d20baba88a8b0e69ff1382aa2e1dc272e05e33a991b204376c3094ad50f28e80e54d34ec }


condition:
	$a0
}