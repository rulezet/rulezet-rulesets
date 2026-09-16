rule Win_Trojan_Twister_2
{
strings:
	$a0 = { 02b44ecd217231ba9e00b8023d90cd21722193b000b457cd215152ba0001b90030b440cd215a }


condition:
	$a0
}