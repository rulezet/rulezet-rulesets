rule Win_Trojan_VGEN_315
{
strings:
	$a0 = { afc55d0a8847ffb010ab03c2abcd278d7f408bf2601e57803c2ea475fa66c704434f4d00b84558ab98ab5fb456cd21 }


condition:
	$a0
}