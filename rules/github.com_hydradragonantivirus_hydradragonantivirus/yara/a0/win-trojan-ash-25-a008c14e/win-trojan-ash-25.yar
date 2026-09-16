rule Win_Trojan_Ash_25
{
strings:
	$a0 = { e800005d81ed????8db6??01bf0001a5a5b41a8d96????cd21b44e }


condition:
	$a0
}