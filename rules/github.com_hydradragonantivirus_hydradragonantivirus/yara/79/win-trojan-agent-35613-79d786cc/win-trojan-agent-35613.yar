rule Win_Trojan_Agent_35613
{
strings:
	$a0 = { 6a00ff1528104000e828feffff6a00ff15001040 }

	$a1 = { 3f3f3340594158504158405a }


condition:
	$a0 and $a1
}