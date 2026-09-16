rule Win_Trojan_Ohlala_1
{
strings:
	$a0 = { 2e8a042e308129002e8a81290089fe29c6434ee2eb }


condition:
	$a0
}