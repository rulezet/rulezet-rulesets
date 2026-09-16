rule Win_Trojan_B_33
{
strings:
	$a0 = { 4a02b42acd2180fa0d753455b91d00be2a02e8480132c050b9280033db33d2cd2658720bb91d00ba2a0243b440cd }


condition:
	$a0
}