rule Win_Trojan_Deicide_5
{
strings:
	$a0 = { 3002b91b00cd21b440ba00f1b94b01cd21b442b00033c933d2cd21 }


condition:
	$a0
}