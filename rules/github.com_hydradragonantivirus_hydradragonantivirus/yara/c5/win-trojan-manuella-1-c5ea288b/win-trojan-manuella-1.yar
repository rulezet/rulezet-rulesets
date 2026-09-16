rule Win_Trojan_Manuella_1
{
strings:
	$a0 = { 81ed030150584c4c5b2bc374042ecd1990b8554bcd213d45527452b82135cd212e8c86b0022e899eae028cd8488ec0 }


condition:
	$a0
}