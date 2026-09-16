rule Win_Trojan_NSIS_13
{
strings:
	$a0 = { 6566656e63652e65786500687474703a2f2f7777772e69697376 }


condition:
	$a0
}