rule Win_Trojan_Liberty_5
{
strings:
	$a0 = { bb5c018b0f1e5b03cb1e51b9100151cb }


condition:
	$a0
}