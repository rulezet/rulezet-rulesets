rule Win_Trojan_Velvet_1
{
strings:
	$a0 = { 40ba0001b97805cd21b8024233c933d2cd21b440b9780533d21e8eddcd2133c08ed832edbe6c04 }


condition:
	$a0
}