rule Win_Trojan_C_1
{
strings:
	$a0 = { be000187f757a5a48d966d02b41acd21b74e93b907008d963b02cd217215b90d008db68b }


condition:
	$a0
}