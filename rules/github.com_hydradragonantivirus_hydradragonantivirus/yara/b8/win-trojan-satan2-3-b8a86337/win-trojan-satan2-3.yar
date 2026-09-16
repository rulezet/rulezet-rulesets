rule Win_Trojan_Satan2_3
{
strings:
	$a0 = { e80000fc0e1f8bec826e00035ebb2400b906082bcb823064fe0843e2f8b8020303c650c3 }


condition:
	$a0
}