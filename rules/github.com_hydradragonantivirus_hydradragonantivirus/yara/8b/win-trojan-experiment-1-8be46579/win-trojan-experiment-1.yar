rule Win_Trojan_Experiment_1
{
strings:
	$a0 = { 1acd21b44732d28db67f01cd21b44e8d961c0133c9cd21 }


condition:
	$a0
}