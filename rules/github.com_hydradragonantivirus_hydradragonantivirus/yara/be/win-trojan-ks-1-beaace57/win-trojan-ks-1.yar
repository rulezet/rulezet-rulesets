rule Win_Trojan_Ks_1
{
strings:
	$a0 = { 0103b90600cd7f720bb80103bb0001b90100cd7fe81e0033c08ec0b80102bb007cb90600ba8000 }


condition:
	$a0
}