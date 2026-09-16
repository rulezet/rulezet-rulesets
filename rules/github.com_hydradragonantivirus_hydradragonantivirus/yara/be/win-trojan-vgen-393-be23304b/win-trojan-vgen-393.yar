rule Win_Trojan_VGEN_393
{
strings:
	$a0 = { 93b447b200beee01cd21b44eb92700bad201cd217318bacf01b43bcd2173ebbaee01b43bcd21b409bad601cd21c32e }


condition:
	$a0
}