rule Win_Trojan_Banker_6324
{
strings:
	$a0 = { 558bec83c4f0b8c8a74800e8f0b2f7ffa178d348 }

	$a1 = { 7365677572616e }


condition:
	$a0 and $a1
}