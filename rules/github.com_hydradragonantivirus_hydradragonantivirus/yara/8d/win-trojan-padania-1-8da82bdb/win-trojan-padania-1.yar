rule Win_Trojan_Padania_1
{
strings:
	$a0 = { 1000c0b9001000008b1881fb002000c0721181fb000002c07709817b0c564d4d20740540e2e2 }


condition:
	$a0
}