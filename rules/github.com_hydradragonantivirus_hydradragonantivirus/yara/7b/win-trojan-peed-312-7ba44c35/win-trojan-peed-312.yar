rule Win_Trojan_Peed_312
{
strings:
	$a0 = { 4885c0754bab50525183c8ff4005d98a400029db8b085353ffd193595a5801df }


condition:
	$a0
}