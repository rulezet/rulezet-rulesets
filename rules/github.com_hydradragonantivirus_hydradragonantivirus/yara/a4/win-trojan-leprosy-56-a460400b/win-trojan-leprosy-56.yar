rule Win_Trojan_Leprosy_56
{
strings:
	$a0 = { 8a27[0-1]3226??01[0-1]8827[0-3]81fb5c03[0-1]7eeb }


condition:
	$a0
}