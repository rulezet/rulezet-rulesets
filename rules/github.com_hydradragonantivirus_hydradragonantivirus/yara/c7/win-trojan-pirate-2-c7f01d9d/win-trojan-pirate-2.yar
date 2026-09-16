rule Win_Trojan_Pirate_2
{
strings:
	$a0 = { 8a36f47d8a2ef27d8a0ef17db801039cff1e247cfcbe0b7abf0b7cb91900f3a4c606f37d00 }


condition:
	$a0
}