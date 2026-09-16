rule Win_Trojan_Agent_34209
{
strings:
	$a0 = { 414933d957890c24331c2483c404 }


condition:
	$a0
}