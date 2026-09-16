rule Win_Trojan_Trojan_131
{
strings:
	$a0 = { 90a007f7b9400133d2cd269d803e06f7027519b003b9 }


condition:
	$a0
}