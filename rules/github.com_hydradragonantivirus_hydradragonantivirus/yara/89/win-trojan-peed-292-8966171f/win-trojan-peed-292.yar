rule Win_Trojan_Peed_292
{
strings:
	$a0 = { e89800000068c07600005981c1005f000081c1c0760000baff }


condition:
	$a0
}