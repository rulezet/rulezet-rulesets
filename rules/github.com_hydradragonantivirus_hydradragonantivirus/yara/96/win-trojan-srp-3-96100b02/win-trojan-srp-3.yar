rule Win_Trojan_Srp_3
{
strings:
	$a0 = { 60fa8cd02ea317002e892615000e1f0e070e17bce810e820008cc82b06130001060f00faa117008ed08b261500 }


condition:
	$a0
}