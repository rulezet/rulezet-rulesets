rule Win_Trojan_Patched_148
{
strings:
	$a0 = { 5bbf7a1d807c8d73??8a0e84c9740b8d460550ffd783c610ebef8d73 }


condition:
	$a0
}