rule Win_Trojan_JoshiBoot_1
{
strings:
	$a0 = { 0800bb0400f7e38bf0b8ce01263b04 }


condition:
	$a0
}