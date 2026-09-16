rule Win_Trojan_Plague_4
{
strings:
	$a0 = { 34018a273226060188274381fb8303 }


condition:
	$a0
}