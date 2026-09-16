rule Win_Trojan_Getit_1
{
strings:
	$a0 = { 1e1001e95bff90b81601a31401b82135cd21bf1001891d8c4502bab1020e1fb82125cd21bacf03 }


condition:
	$a0
}