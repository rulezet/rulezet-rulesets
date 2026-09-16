rule Win_Trojan_ARCV_23
{
strings:
	$a0 = { 515250e86dfd2e8384c30301e822ffe8d8ff585a595bcd }


condition:
	$a0
}