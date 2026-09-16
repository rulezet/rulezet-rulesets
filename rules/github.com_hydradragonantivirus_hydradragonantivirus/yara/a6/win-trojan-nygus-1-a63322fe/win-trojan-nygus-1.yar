rule Win_Trojan_Nygus_1
{
strings:
	$a0 = { 40cd21b002e82b00b1a3ba0501b440e82a00b43ecd21b4 }


condition:
	$a0
}