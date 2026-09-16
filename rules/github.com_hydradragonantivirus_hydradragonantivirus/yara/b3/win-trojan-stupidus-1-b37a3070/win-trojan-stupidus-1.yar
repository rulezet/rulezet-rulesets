rule Win_Trojan_Stupidus_1
{
strings:
	$a0 = { 058bcb412e8a0781fb1e007204349404242e88074be2ed }


condition:
	$a0
}