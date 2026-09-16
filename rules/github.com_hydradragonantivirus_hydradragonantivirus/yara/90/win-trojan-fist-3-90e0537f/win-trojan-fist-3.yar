rule Win_Trojan_Fist_3
{
strings:
	$a0 = { 02018a160101b96b02300430d0fec0f6d230c246e2f3 }


condition:
	$a0
}