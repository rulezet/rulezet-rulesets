rule Win_Trojan_Goma_20
{
strings:
	$a0 = { 864704899649045bb91a00b440b9d9028d960001cd21b8004233c999cd21b440b91a008d964504 }


condition:
	$a0
}