rule Win_Trojan_July13_1
{
strings:
	$a0 = { 2ea0????34??be1200b9af042e300446e2fa }


condition:
	$a0
}