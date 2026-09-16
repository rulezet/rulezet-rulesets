rule Win_Trojan_VGEN_202
{
strings:
	$a0 = { 0400cd038dbeb802ffd7c02dabc72bc2da2b930f1ee60aa7ad2d28a2b52f28d1dcf7abed2bdcf7d0a6bd5729930f0e }


condition:
	$a0
}