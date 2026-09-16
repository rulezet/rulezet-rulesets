rule Win_Trojan_Rape_2
{
strings:
	$a0 = { 6972cbbae702b90300b440cd6972bf }


condition:
	$a0
}