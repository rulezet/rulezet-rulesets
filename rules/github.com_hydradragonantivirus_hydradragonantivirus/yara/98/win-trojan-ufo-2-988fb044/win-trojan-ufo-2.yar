rule Win_Trojan_UFO_2
{
strings:
	$a0 = { 052e8c06c3050e07bb0300b922012ea0060026300743e2fabb5001b96c0426300743e2fa }


condition:
	$a0
}