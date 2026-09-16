rule Win_Trojan_Zipper_1
{
strings:
	$a0 = { e800005b83eb068a3605018beb28771843e2fa9090 }


condition:
	$a0
}