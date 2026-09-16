rule Win_Trojan_Trivial_44
{
strings:
	$a0 = { b162b440cd21b000e81300c7044de9897c02b440cd21b43ecd21b44febc3b4429933c9cd21b104 }


condition:
	$a0
}