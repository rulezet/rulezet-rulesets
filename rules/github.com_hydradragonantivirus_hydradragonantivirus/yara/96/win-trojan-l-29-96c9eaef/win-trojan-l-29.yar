rule Win_Trojan_L_29
{
strings:
	$a0 = { 2201525bffd3e9c10d198b1ec80e53e80f005bb93f10ba0001b440cd21e80100c3bb38018a2732 }


condition:
	$a0
}