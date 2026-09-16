rule Win_Trojan_Hal_3
{
strings:
	$a0 = { 20ed3b1aa426b426188b87a834d647320a08a170d0b6f4fe }


condition:
	$a0
}