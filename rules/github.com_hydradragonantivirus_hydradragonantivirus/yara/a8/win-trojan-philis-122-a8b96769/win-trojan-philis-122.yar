rule Win_Trojan_Philis_122
{
strings:
	$a0 = { 53562bdf2bf05e5b60535be80000000057d3cf5f }


condition:
	$a0
}