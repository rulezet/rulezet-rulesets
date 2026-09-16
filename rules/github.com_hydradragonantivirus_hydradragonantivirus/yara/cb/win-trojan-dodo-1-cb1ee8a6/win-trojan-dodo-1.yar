rule Win_Trojan_Dodo_1
{
strings:
	$a0 = { b4bacd2180fcab7502eb31b82135cd211e06b810005007 }


condition:
	$a0
}