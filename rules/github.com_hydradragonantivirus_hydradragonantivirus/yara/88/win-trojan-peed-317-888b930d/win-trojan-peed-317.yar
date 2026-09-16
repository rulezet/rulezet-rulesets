rule Win_Trojan_Peed_317
{
strings:
	$a0 = { 4885c0754bab50525183c8ff4005d9??400029db8b085353ffd19359 }


condition:
	$a0
}