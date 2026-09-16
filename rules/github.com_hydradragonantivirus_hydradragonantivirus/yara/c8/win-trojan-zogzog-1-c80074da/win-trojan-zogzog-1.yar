rule Win_Trojan_Zogzog_1
{
strings:
	$a0 = { 8b6e008bf581ed28012e803c4d75432e807c015a753cfa2e8c9648012e89a64a018cc88ed0bcc409fbe83a007403 }


condition:
	$a0
}