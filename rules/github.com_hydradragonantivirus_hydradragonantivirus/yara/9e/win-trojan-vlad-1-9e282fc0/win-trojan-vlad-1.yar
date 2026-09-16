rule Win_Trojan_VLAD_1
{
strings:
	$a0 = { cd3eb421cd00f7ba1f0e0010b940b421cdd231c9314200b821cd0117b940b4fae2aafdacfc }


condition:
	$a0
}