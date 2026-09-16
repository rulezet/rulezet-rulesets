rule Win_Trojan_Dikshev_24
{
strings:
	$a0 = { 2e652ab99e00b44e87ce8bd1cd217301c38bd6ac3c2e75fb66c704636f6d20b45bcd2172eb93b440b22f87 }


condition:
	$a0
}