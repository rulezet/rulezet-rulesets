rule Win_Trojan_Misis_1
{
strings:
	$a0 = { c98ed98ed1bc007cfc8bdcb801028ec041ba8000cd13721b26813f33c97414b80103b10650cd13588bf4 }


condition:
	$a0
}