rule Win_Trojan_VGEN_755
{
strings:
	$a0 = { bf000526803d07741a9090be0001b94d00fcf3a48ed9be8400a5a5b82125ba4705cd2106c360b8013dcd2172159090 }


condition:
	$a0
}