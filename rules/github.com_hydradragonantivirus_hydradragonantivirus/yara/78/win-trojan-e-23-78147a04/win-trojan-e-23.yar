rule Win_Trojan_E_23
{
strings:
	$a0 = { 2150b452cd2126c45f120bdb75188cc03dffff74088ede9626c41febf133ff8905894502eb2526c51f8b7f028b }


condition:
	$a0
}