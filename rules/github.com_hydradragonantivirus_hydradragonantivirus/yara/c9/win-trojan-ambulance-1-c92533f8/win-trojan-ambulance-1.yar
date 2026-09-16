rule Win_Trojan_Ambulance_1
{
strings:
	$a0 = { 018a0788058b4701894501ffe7c3e8 }


condition:
	$a0
}