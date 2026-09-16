rule Win_Trojan_C_83
{
strings:
	$a0 = { e800005d81ed0600508db61b008bfeb9f800ac34 }


condition:
	$a0
}