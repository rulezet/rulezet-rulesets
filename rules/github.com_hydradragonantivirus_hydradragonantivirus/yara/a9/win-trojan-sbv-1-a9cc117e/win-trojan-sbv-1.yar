rule Win_Trojan_SBV_1
{
strings:
	$a0 = { 803e3e022e743126803e1502f07529b8010333d2b60133c9b10ee828007219fcbe0302bf0300b9 }


condition:
	$a0
}