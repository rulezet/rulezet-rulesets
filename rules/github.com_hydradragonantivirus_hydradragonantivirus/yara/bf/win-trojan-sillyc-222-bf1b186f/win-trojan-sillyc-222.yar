rule Win_Trojan_SillyC_222
{
strings:
	$a0 = { 8cc88ec08ed8e800005d8bf583ee48bf0001b90300fcf3a4bb90008bc52dc2ffe82700b41a8bd583ea3fcd21b44e }


condition:
	$a0
}