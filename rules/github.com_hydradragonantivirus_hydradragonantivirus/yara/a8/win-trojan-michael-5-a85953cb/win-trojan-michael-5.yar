rule Win_Trojan_Michael_5
{
strings:
	$a0 = { c08ed88ed0bc007cfba11304a3707d2d0300a31304b106d3e0a39a7d8ec0be007c33ffb90001fcf3a5ff2e987d33 }


condition:
	$a0
}