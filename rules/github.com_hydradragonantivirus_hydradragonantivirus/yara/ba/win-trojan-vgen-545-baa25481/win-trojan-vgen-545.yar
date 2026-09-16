rule Win_Trojan_VGEN_545
{
strings:
	$a0 = { 0300e958ff061e5756525153500e07b90800bacd058bfa58abe2fc33c0abab0e1fb451e8050093 }


condition:
	$a0
}