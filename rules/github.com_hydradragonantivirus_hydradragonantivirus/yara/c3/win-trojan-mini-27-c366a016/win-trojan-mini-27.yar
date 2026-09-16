rule Win_Trojan_Mini_27
{
strings:
	$a0 = { 030097b440508bd552b98c0090cd21b8004233c933d2cd21fdc64611e9897e12fc5a5883c211b9 }


condition:
	$a0
}