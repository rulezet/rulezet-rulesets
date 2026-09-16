rule Win_Trojan_Tenerife_1
{
strings:
	$a0 = { 0801c706060105002ea39900b8004233c933d28b1e1a01cd44b4408b1e1a01b91c00baf200cd44 }


condition:
	$a0
}