rule Win_Trojan_EDV_3
{
strings:
	$a0 = { 7cb90827b601b801029c2eff1e000273 }


condition:
	$a0
}