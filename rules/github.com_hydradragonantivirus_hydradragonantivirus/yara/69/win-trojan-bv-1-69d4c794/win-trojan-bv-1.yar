rule Win_Trojan_Bv_1
{
strings:
	$a0 = { 812f4b024343e2f733034b5a78144c8d332151106a10528f09f34c8f01fb4ca7efa7efa71189e4054cb6658fe1704ecf }


condition:
	$a0
}