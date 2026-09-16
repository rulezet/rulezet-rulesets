rule Win_Trojan_Scar_18
{
strings:
	$a0 = { 5f416e642044656c6574654d652e626174 }


condition:
	$a0
}