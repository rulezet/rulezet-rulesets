rule Win_Trojan_VGEN_700
{
strings:
	$a0 = { e82a01e84000e80900e82f01b000b44ccd218cc88ed8be0303bf9800b90001f3a4ba1d06b000b43dcd2172198b }


condition:
	$a0
}