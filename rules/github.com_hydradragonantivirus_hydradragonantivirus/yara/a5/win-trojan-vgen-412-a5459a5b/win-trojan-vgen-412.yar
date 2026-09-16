rule Win_Trojan_VGEN_412
{
strings:
	$a0 = { bf000526803d077418be0001b94800fcf3a48ed9be8400a5a5b82125ba4205cd2106c360b8013dcd217213931e0e1f }


condition:
	$a0
}