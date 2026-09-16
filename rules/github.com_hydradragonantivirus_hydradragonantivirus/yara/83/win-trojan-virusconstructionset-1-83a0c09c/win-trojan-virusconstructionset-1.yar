rule Win_Trojan_VirusConstructionSet_1
{
strings:
	$a0 = { e814008aa42f058dbc2001b90f0489fe }


condition:
	$a0
}