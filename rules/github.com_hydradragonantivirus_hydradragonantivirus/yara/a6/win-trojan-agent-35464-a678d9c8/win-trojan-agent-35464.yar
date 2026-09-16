rule Win_Trojan_Agent_35464
{
strings:
	$a0 = { b85c0e50005064ff3500000000648925 }

	$a1 = { 526573747500 }

	$a2 = { 4f666669636520576f7264 }


condition:
	$a0 and $a1 and $a2
}