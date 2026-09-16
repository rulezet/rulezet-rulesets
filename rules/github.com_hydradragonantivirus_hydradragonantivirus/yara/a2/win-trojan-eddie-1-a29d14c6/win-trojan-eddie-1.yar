rule Win_Trojan_Eddie_1
{
strings:
	$a0 = { 0226a186002e89877e02b85aa5cd21 }


condition:
	$a0
}