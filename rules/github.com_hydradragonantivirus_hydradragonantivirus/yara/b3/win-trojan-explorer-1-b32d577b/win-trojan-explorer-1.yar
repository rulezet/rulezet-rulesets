rule Win_Trojan_Explorer_1
{
strings:
	$a0 = { 740bb9e8092e300446fec0e2f8c32ea0da002ea20e002ec606da0000bef2012ea0db0b2e2a }


condition:
	$a0
}