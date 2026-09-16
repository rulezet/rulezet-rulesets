rule Win_Trojan_Breaktime_1
{
strings:
	$a0 = { 0100641b69044d41494e642969094175746f436c6f7365641a1b }


condition:
	$a0
}