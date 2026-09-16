rule Win_Trojan_B_120
{
strings:
	$a0 = { 03ba8000bb0002b90100e84500c3b404cd1a720a86f286ce81fa02927206 }


condition:
	$a0
}