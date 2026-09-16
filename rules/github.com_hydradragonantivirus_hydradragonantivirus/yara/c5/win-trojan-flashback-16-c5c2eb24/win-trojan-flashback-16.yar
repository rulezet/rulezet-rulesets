rule Win_Trojan_Flashback_16
{
strings:
	$a0 = { 557365722d4167656e7400484f4d4500494f536572766963653a }


condition:
	$a0
}