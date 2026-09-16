rule Win_Trojan_Agent_35434
{
strings:
	$a0 = { e925e4ffff0000002507bbaf1e4c080000000000000000003e4c }


condition:
	$a0
}