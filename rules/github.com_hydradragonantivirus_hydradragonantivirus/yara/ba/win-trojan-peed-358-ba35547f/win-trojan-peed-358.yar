rule Win_Trojan_Peed_358
{
strings:
	$a0 = { e89800000068c07600005981c1005f000081c1c0 }


condition:
	$a0
}