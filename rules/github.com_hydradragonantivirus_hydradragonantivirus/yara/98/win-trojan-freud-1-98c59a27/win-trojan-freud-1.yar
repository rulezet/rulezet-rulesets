rule Win_Trojan_Freud_1
{
strings:
	$a0 = { 5b83eb048a1781eb9d0780fa007416eb05908d9e0c018af2b98d0730172ad680ee2e43e2f6 }


condition:
	$a0
}