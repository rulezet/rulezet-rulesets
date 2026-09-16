rule Win_Trojan_Tiny_15
{
strings:
	$a0 = { b29ecd2193b43f5459ba4e01cd213854547412fec45033c9f7e1b442cd218bd659b440cd21b44f }


condition:
	$a0
}