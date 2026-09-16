rule Win_Trojan_Blackhole_39
{
strings:
	$a0 = { 4e756d6265723a20094c6f6164696e67 }


condition:
	$a0
}