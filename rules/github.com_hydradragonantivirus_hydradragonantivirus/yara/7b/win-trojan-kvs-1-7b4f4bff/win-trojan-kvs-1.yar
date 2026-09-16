rule Win_Trojan_KVS_1
{
strings:
	$a0 = { 960781c2960781c22c01b104d3ea42cd212eff36e0041f }


condition:
	$a0
}