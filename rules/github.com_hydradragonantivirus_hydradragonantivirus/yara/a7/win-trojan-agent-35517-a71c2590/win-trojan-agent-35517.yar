rule Win_Trojan_Agent_35517
{
strings:
	$a0 = { 558bec6aff688820400068c419400064a1000000005064 }


condition:
	$a0
}