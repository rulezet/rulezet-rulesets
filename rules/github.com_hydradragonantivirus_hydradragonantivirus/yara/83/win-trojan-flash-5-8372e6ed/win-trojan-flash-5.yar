rule Win_Trojan_Flash_5
{
strings:
	$a0 = { 1ffce800005e8bde83c30eb000fad50a8807eb10ea }


condition:
	$a0
}