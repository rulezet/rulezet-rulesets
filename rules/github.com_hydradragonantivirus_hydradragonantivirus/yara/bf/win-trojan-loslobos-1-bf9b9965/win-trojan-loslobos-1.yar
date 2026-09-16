rule Win_Trojan_LosLobos_1
{
strings:
	$a0 = { 04b44ccd218db60301bf0001fca5a4b02a8ae0cd213c00 }


condition:
	$a0
}