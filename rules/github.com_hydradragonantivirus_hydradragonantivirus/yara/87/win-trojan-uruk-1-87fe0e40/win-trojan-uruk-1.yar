rule Win_Trojan_Uruk_1
{
strings:
	$a0 = { 4b7565b80043cd7b80e13eb80143cd7bb8023dcd }


condition:
	$a0
}