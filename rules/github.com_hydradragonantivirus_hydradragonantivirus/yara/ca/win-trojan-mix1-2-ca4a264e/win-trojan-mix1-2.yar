rule Win_Trojan_MIX1_2
{
strings:
	$a0 = { b800008ec0be7103268b3e840083c70a }


condition:
	$a0
}