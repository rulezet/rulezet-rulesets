rule Win_Trojan_Bla_1
{
strings:
	$a0 = { 0290b440cd21b8004233c933d2cd2181c77302c60503c64501018b451fc64502e92d0500 }


condition:
	$a0
}