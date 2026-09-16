rule Win_Trojan_K_19
{
strings:
	$a0 = { ba00008b9ccc02b002b442cd217303e9c3008984ca }


condition:
	$a0
}