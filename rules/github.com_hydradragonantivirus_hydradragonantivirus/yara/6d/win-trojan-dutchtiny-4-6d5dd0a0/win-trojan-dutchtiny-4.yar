rule Win_Trojan_DutchTiny_4
{
strings:
	$a0 = { 3c4d7428b002e82b0097b175b440cd21b000e81f00c7044de9897c02b440cd21b43ecd21ba8000 }


condition:
	$a0
}