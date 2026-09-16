rule Win_Trojan_Tiny_98
{
strings:
	$a0 = { 33c033c9e8????1e6a00cb[0-175]33ffbe????1eb0??8ec0 }


condition:
	$a0
}