rule Win_Trojan_Maljava_2
{
strings:
	$a0 = { 5061796c6f6164582e6a617661 }

	$a1 = { 6d73662f782f5061796c6f616458 }


condition:
	$a0 and $a1
}