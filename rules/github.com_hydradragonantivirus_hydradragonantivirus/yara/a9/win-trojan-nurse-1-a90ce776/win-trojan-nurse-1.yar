rule Win_Trojan_Nurse_1
{
strings:
	$a0 = { 5d81ed0300eb7a90bb210003ddb911012e8a17d0ca2e881743e2f5eb64905352508b1e4d01b104d3e32bc383da }


condition:
	$a0
}