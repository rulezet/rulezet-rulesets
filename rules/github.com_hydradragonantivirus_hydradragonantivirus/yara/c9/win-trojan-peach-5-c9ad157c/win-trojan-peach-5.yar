rule Win_Trojan_Peach_5
{
strings:
	$a0 = { 1e27040e1fa33201891e3401890e3601 }


condition:
	$a0
}