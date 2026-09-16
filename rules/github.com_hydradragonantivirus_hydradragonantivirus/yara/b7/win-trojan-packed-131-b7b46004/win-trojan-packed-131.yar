rule Win_Trojan_Packed_131
{
strings:
	$a0 = { 558bec6aff68a020400068001a400064a100000000506489250000000083ec68 }

	$a1 = { 736f6d656e69677a }


condition:
	$a0 and $a1
}