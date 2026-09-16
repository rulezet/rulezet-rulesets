rule Win_Trojan_USSR_30
{
strings:
	$a0 = { 33ff8bf383ee03b8044bcd213d4b04 }


condition:
	$a0
}