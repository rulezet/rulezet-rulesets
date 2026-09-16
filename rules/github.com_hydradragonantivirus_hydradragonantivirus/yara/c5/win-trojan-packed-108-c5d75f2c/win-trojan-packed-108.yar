rule Win_Trojan_Packed_108
{
strings:
	$a0 = { b9e3b1b3e7e1b1b3b7dd2fadb900b1b381c3b7e32e3826142e4826042e5826342e6826242e782654b7ddafb12e882644 }


condition:
	$a0
}