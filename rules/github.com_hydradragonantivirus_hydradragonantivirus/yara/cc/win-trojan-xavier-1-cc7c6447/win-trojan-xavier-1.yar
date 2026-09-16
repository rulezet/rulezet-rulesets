rule Win_Trojan_XAVIER_1
{
strings:
	$a0 = { ba0002b96f01cd21e83400ba5e03b440b90300cd21b80157ba0000b9000080e1e080c91fcd21 }


condition:
	$a0
}