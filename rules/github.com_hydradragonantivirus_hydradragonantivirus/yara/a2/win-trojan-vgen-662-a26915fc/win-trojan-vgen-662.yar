rule Win_Trojan_VGEN_662
{
strings:
	$a0 = { 90e19d2ea58c6b8664894d96248cc8488ed8803e00005a7544a103002d4000a303008bd88cc003c38ec0b9e2008c }


condition:
	$a0
}