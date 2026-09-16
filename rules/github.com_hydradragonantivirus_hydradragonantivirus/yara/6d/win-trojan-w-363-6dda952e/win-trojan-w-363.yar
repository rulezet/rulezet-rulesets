rule Win_Trojan_W_363
{
strings:
	$a0 = { 8db55601000051ad03c52d000041008bf8b906000000f3a459e2eb61c3f5004100cd20530001 }


condition:
	$a0
}