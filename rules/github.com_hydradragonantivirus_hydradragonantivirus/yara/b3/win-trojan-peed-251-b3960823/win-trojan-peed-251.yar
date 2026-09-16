rule Win_Trojan_Peed_251
{
strings:
	$a0 = { badb74a40a85f387d773495589e55150b80100000048506a00 }


condition:
	$a0
}