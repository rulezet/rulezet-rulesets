rule Win_Trojan_VGEN_653
{
strings:
	$a0 = { ff09dbb42acd217b144bb430cd2101f7b42acd2101db81da45b6be397fb42ccd2121ff83c335b419cd2131ef85fb }


condition:
	$a0
}