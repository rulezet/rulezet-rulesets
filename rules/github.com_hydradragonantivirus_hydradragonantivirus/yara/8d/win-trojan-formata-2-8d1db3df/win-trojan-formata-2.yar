rule Win_Trojan_FormatA_2
{
strings:
	$a0 = { b500ba00008ec2bb0000cd13ba1a01b409cd21b44ccd2142652048617070792e2e2e24 }


condition:
	$a0
}