rule Win_Trojan_Peed_161
{
strings:
	$a0 = { 71186800??40815a01c2528b020??????????828000000e2f2c37705685635ff00ba43??400081c278460000ff125ec1 }


condition:
	$a0
}