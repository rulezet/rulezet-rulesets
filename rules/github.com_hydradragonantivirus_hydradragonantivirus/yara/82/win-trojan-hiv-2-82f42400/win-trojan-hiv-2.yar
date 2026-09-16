rule Win_Trojan_HIV_2
{
strings:
	$a0 = { c4064c002e898495fb2e8c8497fbc41e }


condition:
	$a0
}