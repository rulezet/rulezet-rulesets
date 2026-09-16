rule Win_Trojan_Shire_1
{
strings:
	$a0 = { 8d5465cd217210d00eb0ffb44f72f4bab4ffb8023dcd }


condition:
	$a0
}