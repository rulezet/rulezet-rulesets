rule Win_Trojan_Mutant_5
{
strings:
	$a0 = { 3fcd21058000813ec2014449741350 }


condition:
	$a0
}