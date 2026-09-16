rule Win_Trojan_Trojan_165
{
strings:
	$a0 = { 02ac0ac075fb817cfc45587444817cfc434f7532807c }


condition:
	$a0
}