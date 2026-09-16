rule Win_Trojan_Ugly_4
{
strings:
	$a0 = { 8ed0bc007c0e1fb9b301bb177c5180372043e2fa }


condition:
	$a0
}