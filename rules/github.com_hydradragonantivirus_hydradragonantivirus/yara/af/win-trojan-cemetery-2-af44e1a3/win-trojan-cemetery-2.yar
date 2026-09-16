rule Win_Trojan_Cemetery_2
{
strings:
	$a0 = { fca102013d00f07569b280a10601 }


condition:
	$a0
}