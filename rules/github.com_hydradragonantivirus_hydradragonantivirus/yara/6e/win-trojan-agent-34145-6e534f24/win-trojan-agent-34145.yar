rule Win_Trojan_Agent_34145
{
strings:
	$a0 = { e804000000a9cea271e805000000380e6824005283ecfc83ecfc83ecfc68ba704000516860 }


condition:
	$a0
}