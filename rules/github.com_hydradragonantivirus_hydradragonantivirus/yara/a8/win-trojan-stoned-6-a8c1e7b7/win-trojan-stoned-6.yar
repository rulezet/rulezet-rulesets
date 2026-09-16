rule Win_Trojan_Stoned_6
{
strings:
	$a0 = { 0400b801020e07bb0002b9010033d29c }


condition:
	$a0
}