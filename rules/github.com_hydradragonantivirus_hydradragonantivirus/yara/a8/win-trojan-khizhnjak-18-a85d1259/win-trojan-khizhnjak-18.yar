rule Win_Trojan_Khizhnjak_18
{
strings:
	$a0 = { 01b94a028b1eba02b440cd217222b90000ba00008b1eba02b000b442cd217210babc02b90300 }


condition:
	$a0
}