rule Win_Trojan_Lobo_1
{
strings:
	$a0 = { 53512e8b1e1d018bc3b94a05302f30074340e2f8595b582eff261d01 }


condition:
	$a0
}