rule Win_Trojan_Whale_18
{
strings:
	$a0 = { f1ffb99f2329cb83e91ae8170075fb }


condition:
	$a0
}