rule Win_Trojan_Duwende_4
{
strings:
	$a0 = { 7a18dfc4f915f8e2fc25e06fe271af2ff619e271a7b7a15638709f6fa7ed6c40a7e3e23c4efbb3b8fe58fcc4842a4575 }


condition:
	$a0
}