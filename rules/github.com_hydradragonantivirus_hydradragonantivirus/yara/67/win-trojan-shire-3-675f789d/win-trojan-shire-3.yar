rule Win_Trojan_Shire_3
{
strings:
	$a0 = { 8300cd217210d00eb2ffb44f72f4bab6ffb8023d }


condition:
	$a0
}