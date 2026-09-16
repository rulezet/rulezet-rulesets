rule Win_Trojan_Tosha_2
{
strings:
	$a0 = { fe7338813e2e032c017230b440ba0002b94101cd21b8004233d233c9cd21c6063003e9a12e03 }


condition:
	$a0
}