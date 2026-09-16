rule Win_Trojan_NextGen_1
{
strings:
	$a0 = { eb0023c0eb00eb00e8000058e2f2b000b96908bb31002e300743e2fa }


condition:
	$a0
}