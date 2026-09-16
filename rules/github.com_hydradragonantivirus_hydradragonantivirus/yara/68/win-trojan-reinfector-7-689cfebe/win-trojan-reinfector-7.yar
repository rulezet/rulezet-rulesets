rule Win_Trojan_Reinfector_7
{
strings:
	$a0 = { 666f722025256920696e20282a2e626174202e2e2f2a2e62617429 }

	$a1 = { 2667743b626f6f6b6d61726b2e68746d }


condition:
	$a0 and $a1
}