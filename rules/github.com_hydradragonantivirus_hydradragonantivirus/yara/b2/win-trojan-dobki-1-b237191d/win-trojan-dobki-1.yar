rule Win_Trojan_Dobki_1
{
strings:
	$a0 = { 25ba0f01eb0290e8cd21eb0790c6061b0143cfccc6061c0140434080fb0174060ac07402cd20b1b1be46018bfe80 }


condition:
	$a0
}