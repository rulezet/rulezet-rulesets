rule Win_Trojan_Plague_1
{
strings:
	$a0 = { 018a273226060188274381fb83037ef1 }


condition:
	$a0
}