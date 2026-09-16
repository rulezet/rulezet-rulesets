rule Win_Trojan_PC_1
{
strings:
	$a0 = { f8f81657ffb6fefc8dbef8fc16579ac705200183befefc00740d8b86f8fc3b86fefc7503e90b }


condition:
	$a0
}