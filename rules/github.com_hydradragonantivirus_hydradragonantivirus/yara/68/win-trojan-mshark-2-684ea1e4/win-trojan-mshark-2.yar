rule Win_Trojan_Mshark_2
{
strings:
	$a0 = { e86200b440ba4b0103d6b90400cd217239b80242 }


condition:
	$a0
}