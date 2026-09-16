rule Win_Trojan_PKZ300b_1
{
strings:
	$a0 = { c5000e579aa906ac00bf44001e579a3607ac00bf44001e57b8ff00509ac306ac009a000036008d }


condition:
	$a0
}