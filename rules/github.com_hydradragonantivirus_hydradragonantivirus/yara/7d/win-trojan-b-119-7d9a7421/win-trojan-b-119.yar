rule Win_Trojan_B_119
{
strings:
	$a0 = { b80103cd13b80103bb000133c98af141b280cd13582ea28002b8dc01 }


condition:
	$a0
}