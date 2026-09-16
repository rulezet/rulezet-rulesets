rule Win_Trojan_Whale_21
{
strings:
	$a0 = { 0e1feb13e8e7fff875fa585b5955ff36 }


condition:
	$a0
}