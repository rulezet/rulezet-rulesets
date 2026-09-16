rule Win_Trojan_C_304
{
strings:
	$a0 = { 70306b65277320576f726d47656e }

	$a1 = { 53747269707065722e7761762e657865 }


condition:
	$a0 and $a1
}