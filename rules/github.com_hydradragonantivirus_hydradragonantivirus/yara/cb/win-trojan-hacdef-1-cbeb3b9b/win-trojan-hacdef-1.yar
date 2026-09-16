rule Win_Trojan_Hacdef_1
{
strings:
	$a0 = { c075c7e8b2a9ffff33c05a59596489106877ab4000c3e9538affffebf85f5e5be8bd8effff004d41494e49434f4e000000004861636b657220446566 }


condition:
	$a0
}