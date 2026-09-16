rule Win_Trojan_Timid_4
{
strings:
	$a0 = { 16fcffb93f00b44ecd210ac0750be809007406b44fcd21 }


condition:
	$a0
}