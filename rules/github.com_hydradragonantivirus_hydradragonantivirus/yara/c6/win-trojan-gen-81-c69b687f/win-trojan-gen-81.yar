rule Win_Trojan_Gen_81
{
strings:
	$a0 = { 5d09cd21b43ecd21b8014332ed8a4d0bcd21c31e07ffe5 }


condition:
	$a0
}