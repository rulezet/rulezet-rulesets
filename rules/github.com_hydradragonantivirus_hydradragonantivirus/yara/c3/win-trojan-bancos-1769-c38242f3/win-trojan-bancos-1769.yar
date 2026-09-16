rule Win_Trojan_Bancos_1769
{
strings:
	$a0 = { 0cd11c3a3b96df2d7492f50367c8e3c9ad53ed176bbdb6dfe716c3af3fc85a04543a07ab7bcc47fca10659678d63ee16cbed9a0b2b6c2f5040087fc45301330ac012c7247afd }


condition:
	$a0
}