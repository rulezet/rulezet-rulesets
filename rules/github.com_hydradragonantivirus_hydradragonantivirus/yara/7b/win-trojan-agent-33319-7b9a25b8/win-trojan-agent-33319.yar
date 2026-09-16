rule Win_Trojan_Agent_33319
{
strings:
	$a0 = { 62c41254cfc6a5c0601a9734740e5879cd353c150cac6ace945b89f3baab12f0e3c15b1c0900dc1a0cca15a2bc91131f43cddb908b7cc290a6ba7a6e127fef1ff63a4ff35b1136aad076ad7ee313 }


condition:
	$a0
}