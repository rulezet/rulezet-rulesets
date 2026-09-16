rule Win_Trojan_RP_2
{
strings:
	$a0 = { b404cd1a80fe057503e93c01bb4c008b072ea3407cbb4e008b072ea3427cbb48008b072ea3447c }


condition:
	$a0
}