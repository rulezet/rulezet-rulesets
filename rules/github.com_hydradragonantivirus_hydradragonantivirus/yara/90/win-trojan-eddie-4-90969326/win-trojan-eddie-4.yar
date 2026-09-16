rule Win_Trojan_Eddie_4
{
strings:
	$a0 = { 02750f33ffb9ee06acae7506e2fa }


condition:
	$a0
}