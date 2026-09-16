rule Win_Trojan_Subsys_4
{
strings:
	$a0 = { b825d7c8b84aee3dc13688aacd449542e517e98861f3021bc4b9370b35d2aabe }


condition:
	$a0
}