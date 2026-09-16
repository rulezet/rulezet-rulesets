rule Win_Trojan_Small_179
{
strings:
	$a0 = { 0472313d99fd732c50b9100033d2b440cd218bd1b979010e1fb440cd2158050d00a3010033c9 }


condition:
	$a0
}