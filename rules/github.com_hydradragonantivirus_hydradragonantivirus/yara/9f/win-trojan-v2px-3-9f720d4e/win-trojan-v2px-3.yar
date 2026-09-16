rule Win_Trojan_V2PX_3
{
strings:
	$a0 = { 31054643f8409047e2e9 }


condition:
	$a0
}