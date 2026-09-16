rule Win_Trojan_Lotus_2
{
strings:
	$a0 = { 0e1f33ff8d7619b914098a243e32a34e0988244783e70746e2f0 }


condition:
	$a0
}