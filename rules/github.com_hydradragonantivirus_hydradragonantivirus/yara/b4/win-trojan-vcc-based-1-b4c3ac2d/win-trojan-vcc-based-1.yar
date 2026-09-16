rule Win_Trojan_VCC_based_1
{
strings:
	$a0 = { 030043cd200e1fe800005d81ed0b00eb02cd208db60502bf0001a5a50e1f8d967702b41a }


condition:
	$a0
}