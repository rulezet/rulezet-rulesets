rule Win_Trojan_LosLobos_2
{
strings:
	$a0 = { 0590b44ccd218db60301bf0001fca5a4b02a8ae0cd213c }


condition:
	$a0
}