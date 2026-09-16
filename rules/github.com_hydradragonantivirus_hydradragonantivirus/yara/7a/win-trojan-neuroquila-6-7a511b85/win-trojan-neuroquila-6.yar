rule Win_Trojan_Neuroquila_6
{
strings:
	$a0 = { fc0e8bc01fb42ed10f8d9f0200b44dcd21b8????f7d803c3f57702ebea }


condition:
	$a0
}