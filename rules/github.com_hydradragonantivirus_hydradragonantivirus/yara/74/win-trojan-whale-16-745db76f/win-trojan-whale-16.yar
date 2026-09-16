rule Win_Trojan_Whale_16
{
strings:
	$a0 = { f81fe82300b18481eda1238bdd8523 }


condition:
	$a0
}