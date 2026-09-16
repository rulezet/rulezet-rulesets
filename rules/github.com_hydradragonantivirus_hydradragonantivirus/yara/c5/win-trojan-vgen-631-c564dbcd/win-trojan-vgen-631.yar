rule Win_Trojan_VGEN_631
{
strings:
	$a0 = { 018b161601b933012e311483c602e80300e2f5c3c3b419cd2150b40eb202cd21b44732d28db6c103cd21badb01b4 }


condition:
	$a0
}