rule Win_Trojan_Agent_34144
{
strings:
	$a0 = { e8030000006ee2e768867c1ccf46e804000000d7 }


condition:
	$a0
}