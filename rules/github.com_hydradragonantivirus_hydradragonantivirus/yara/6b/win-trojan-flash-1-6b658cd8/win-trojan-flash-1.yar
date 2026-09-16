rule Win_Trojan_Flash_1
{
strings:
	$a0 = { 5e8bde81c30f00b000fad50a8807eb }


condition:
	$a0
}