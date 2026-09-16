rule Win_Trojan_CosmicDuke_2
{
strings:
	$a0 = { 6e656d657369732d67656d696e61 }


condition:
	$a0
}