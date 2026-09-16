rule Win_Trojan_MzBoot_1
{
strings:
	$a0 = { 5d012bfbc607e9897f01b60041b80103cd185a59b80102cd18595a585e5f1f9dca02 }


condition:
	$a0
}