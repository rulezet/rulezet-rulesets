rule Win_Trojan_Lion_1
{
strings:
	$a0 = { 32058b1ab90700ba8e0403d5cd21b00233d2e85a00 }


condition:
	$a0
}