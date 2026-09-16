rule Win_Trojan_Tunnel_1
{
strings:
	$a0 = { fcb97e018bfe8b964504ad33c2d1c203d1abe2f6c3 }


condition:
	$a0
}