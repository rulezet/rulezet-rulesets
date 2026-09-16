rule Win_Trojan_N_26
{
strings:
	$a0 = { e800005e81ee3f018cddb83254cd213d06107703e960008cd8488ed8803e00005a740b8b1e030001d8408ed8ebee8ed8 }


condition:
	$a0
}