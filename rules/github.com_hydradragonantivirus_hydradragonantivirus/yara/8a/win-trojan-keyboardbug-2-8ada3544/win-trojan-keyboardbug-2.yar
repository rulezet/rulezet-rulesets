rule Win_Trojan_KeyboardBug_2
{
strings:
	$a0 = { 2effb59707bb6e06b92801582e300143e2fa5b1f }


condition:
	$a0
}