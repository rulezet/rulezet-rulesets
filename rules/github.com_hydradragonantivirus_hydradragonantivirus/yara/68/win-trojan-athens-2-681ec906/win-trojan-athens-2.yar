rule Win_Trojan_Athens_2
{
strings:
	$a0 = { 83ed08fc900ebe28001f03f58bfe1eb9b805073e8a660890ac32c4aae2fa }


condition:
	$a0
}