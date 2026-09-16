rule Win_Trojan_Ladefehler_1
{
strings:
	$a0 = { 2e137ce84c0033eda11304a3217cb106d3e08b1e1b7cd3e3d1db2bc3a3257c8ec0d3e848a31304 }


condition:
	$a0
}