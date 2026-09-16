rule Win_Trojan_Micro_4
{
strings:
	$a0 = { 095056572ec6877a00002ec7877b000000b8010050 }


condition:
	$a0
}