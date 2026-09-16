rule Win_Trojan_Danny_1
{
strings:
	$a0 = { 3d01007c03eb5b90b440b90500ba0001cd217303eb4c903bc17403eb4590bf0001b0b8aa57bf }


condition:
	$a0
}