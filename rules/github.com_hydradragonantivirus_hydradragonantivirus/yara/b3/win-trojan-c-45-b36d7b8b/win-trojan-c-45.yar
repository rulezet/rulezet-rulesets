rule Win_Trojan_C_45
{
strings:
	$a0 = { 030133c9cd21723c93b440b90001ba0001cd21b43ecd21b80043fec0ba0301b90300cd21eb0790 }


condition:
	$a0
}