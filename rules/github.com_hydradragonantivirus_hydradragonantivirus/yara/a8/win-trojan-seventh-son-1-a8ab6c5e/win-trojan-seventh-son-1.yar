rule Win_Trojan_Seventh_Son_1
{
strings:
	$a0 = { b82425cd215ab80133cd210e0e1f }


condition:
	$a0
}