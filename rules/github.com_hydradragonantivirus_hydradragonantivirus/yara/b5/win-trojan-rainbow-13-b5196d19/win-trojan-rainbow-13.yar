rule Win_Trojan_Rainbow_13
{
strings:
	$a0 = { bb007c8ed38be38ec3b80502b90d4fba0001cd139aa0 }


condition:
	$a0
}