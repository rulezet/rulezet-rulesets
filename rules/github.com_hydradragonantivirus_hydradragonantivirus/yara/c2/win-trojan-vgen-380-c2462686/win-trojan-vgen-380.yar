rule Win_Trojan_VGEN_380
{
strings:
	$a0 = { c0070033c08ed8a1130433ff33f648b106a31304d3e08ec087064e00a3407db8d70087064c00a33e7d0e1fb900 }


condition:
	$a0
}