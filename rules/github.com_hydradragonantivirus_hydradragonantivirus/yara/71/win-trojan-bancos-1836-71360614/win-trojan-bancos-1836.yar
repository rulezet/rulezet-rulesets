rule Win_Trojan_Bancos_1836
{
strings:
	$a0 = { 7df3ce89cde69f7ef108e7a87512070ca69711518e7cdfe01653f1cd34dfda2e708b27ee29482615389ea5937a1b6d1dbce2c99446e84603e9e26aaedaaf5e698767577dda0a }


condition:
	$a0
}