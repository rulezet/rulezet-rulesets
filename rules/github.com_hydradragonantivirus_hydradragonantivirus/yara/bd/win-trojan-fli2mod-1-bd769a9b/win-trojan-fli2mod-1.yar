rule Win_Trojan_Fli2Mod_1
{
strings:
	$a0 = { 160501b409ba0601cd218cc88ec0bb0000b90100ba8000b403a00401cd13fec53a2e030172f1b9 }


condition:
	$a0
}