rule Win_Trojan_Khizhnjak_26
{
strings:
	$a0 = { 01b9b8028b1ebd02b440cd217222b90000ba00008b1ebd02b000b442cd217210babf02b90300 }


condition:
	$a0
}