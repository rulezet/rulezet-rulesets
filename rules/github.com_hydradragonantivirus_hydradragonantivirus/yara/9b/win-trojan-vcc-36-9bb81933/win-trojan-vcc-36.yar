rule Win_Trojan_VCC_36
{
strings:
	$a0 = { 43cd200e1fe800005d81ed0b00eb02cd208db64204bf0001a5a50e1f8d96b404b41a }


condition:
	$a0
}