rule Win_Trojan_Incubus_1
{
strings:
	$a0 = { 505351e800005e81eed7008dbc0500b96500e80f0031054747d3c0e2f8595b589dc3 }


condition:
	$a0
}