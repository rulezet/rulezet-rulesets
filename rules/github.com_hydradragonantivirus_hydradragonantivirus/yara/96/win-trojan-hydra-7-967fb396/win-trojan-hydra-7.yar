rule Win_Trojan_Hydra_7
{
strings:
	$a0 = { 3fb9ffffbae002cd2105e0022ea3 }


condition:
	$a0
}