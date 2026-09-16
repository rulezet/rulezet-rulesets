rule Win_Trojan_Trojan_65
{
strings:
	$a0 = { bd0d01be10012e8134????46464d75f649eb02cd20e2fae800005849eb02cd20 }


condition:
	$a0
}