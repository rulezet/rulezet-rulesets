rule Win_Trojan_Plaque_1
{
strings:
	$a0 = { e80f005bb94f02ba0001b440cd21e801 }


condition:
	$a0
}