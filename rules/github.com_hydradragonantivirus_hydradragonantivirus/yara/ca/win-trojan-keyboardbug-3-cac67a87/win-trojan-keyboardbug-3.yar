rule Win_Trojan_KeyboardBug_3
{
strings:
	$a0 = { ffb59707bb6e06b92801582e300143e2 }


condition:
	$a0
}