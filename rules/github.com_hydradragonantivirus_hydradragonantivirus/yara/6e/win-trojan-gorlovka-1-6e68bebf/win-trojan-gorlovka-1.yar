rule Win_Trojan_Gorlovka_1
{
strings:
	$a0 = { 1606008e1e0400b44387cfcd2187f9585a1fb457eb09b43feb02b440baec04cd21c3b440ebf9 }


condition:
	$a0
}