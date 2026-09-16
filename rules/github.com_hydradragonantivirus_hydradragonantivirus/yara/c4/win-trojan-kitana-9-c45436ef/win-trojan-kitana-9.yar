rule Win_Trojan_Kitana_9
{
strings:
	$a0 = { 03cd13381f744bc747fe55aab80203b701ebee0e1fff0e1304cd12c1e0068ec033ffb17a }


condition:
	$a0
}