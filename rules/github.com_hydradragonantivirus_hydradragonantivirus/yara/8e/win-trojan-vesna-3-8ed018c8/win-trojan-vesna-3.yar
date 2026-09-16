rule Win_Trojan_Vesna_3
{
strings:
	$a0 = { b440b90300cd21b90000ba0000b002b442cd218bd783ea03b440b9e803cd21b801572e8b5510 }


condition:
	$a0
}