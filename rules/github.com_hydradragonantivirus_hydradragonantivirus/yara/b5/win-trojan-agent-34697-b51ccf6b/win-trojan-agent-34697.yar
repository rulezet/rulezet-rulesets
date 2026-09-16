rule Win_Trojan_Agent_34697
{
strings:
	$a0 = { 558bec6aff689020400068401a400064a10000000050 }

	$a1 = { 5c0000004558504c4f5245522e455845 }


condition:
	$a0 and $a1
}