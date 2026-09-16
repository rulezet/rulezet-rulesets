rule Win_Trojan_MonteCarlo_2
{
strings:
	$a0 = { 1e01501e0e1fb8d8c3b9e705bac328bf1e01b2903015fec247e2f91fc3 }


condition:
	$a0
}