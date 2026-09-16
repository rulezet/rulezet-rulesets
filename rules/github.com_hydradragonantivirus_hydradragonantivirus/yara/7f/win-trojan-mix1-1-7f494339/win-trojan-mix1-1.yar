rule Win_Trojan_MIX1_1
{
strings:
	$a0 = { b800008ec026803e3c037775095f5e59 }


condition:
	$a0
}