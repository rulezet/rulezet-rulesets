rule Win_Trojan_Ambulance_2
{
strings:
	$a0 = { 018a0788058b4701894501ffe7cbe8de008a8428040ac0 }


condition:
	$a0
}