rule Win_Trojan_Agent_34214
{
strings:
	$a0 = { e80500000059595ceb3633db64ff33648923e820000000 }


condition:
	$a0
}