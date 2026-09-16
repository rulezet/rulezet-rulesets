rule Win_Trojan_Gene_6
{
strings:
	$a0 = { b99d03be0b018bfee8 }

	$a1 = { 8a16????ac32c2aae2fac3 }


condition:
	$a0 and $a1
}