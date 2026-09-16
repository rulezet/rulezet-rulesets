rule Win_Trojan_CRLC_2
{
strings:
	$a0 = { b440b92a0233d2cd219ce877009d721fb8004233c9cd217216b440b91800ba0002cd21720a }


condition:
	$a0
}