rule Win_Trojan_Slovakia_9
{
strings:
	$a0 = { e9580081f00f3c4f4048384593bffecfbda15781f5355181cab0204781e1807dbb146784f381c3549981c22ade81e0 }


condition:
	$a0
}