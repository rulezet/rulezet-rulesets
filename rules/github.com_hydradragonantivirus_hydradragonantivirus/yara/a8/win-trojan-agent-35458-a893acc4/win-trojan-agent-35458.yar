rule Win_Trojan_Agent_35458
{
strings:
	$a0 = { 6a606830c94200e8ce060000bf940000008bc7e802fbffff8965 }


condition:
	$a0
}