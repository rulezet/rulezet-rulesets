rule Win_Trojan_Buzus_32
{
strings:
	$a0 = { 686c154000e8f0ffffff00000000000030 }

	$a1 = { 4d53472c204353584e454b5258504b52 }


condition:
	$a0 and $a1
}