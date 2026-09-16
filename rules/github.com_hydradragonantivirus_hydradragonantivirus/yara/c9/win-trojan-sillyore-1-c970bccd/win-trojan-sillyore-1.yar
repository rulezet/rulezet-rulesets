rule Win_Trojan_SillyORE_1
{
strings:
	$a0 = { 0e1fba13010653668f441fcd2fcd2726803f4d75050e07bb0001ea }


condition:
	$a0
}