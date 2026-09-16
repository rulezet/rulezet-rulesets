rule Win_Trojan_Zlob_2331
{
strings:
	$a0 = { 558bec525633d6e9f0080000af10d6267b278927411311550c5d4b563c44183f }


condition:
	$a0
}