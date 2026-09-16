rule Win_Trojan_YZ_3
{
strings:
	$a0 = { 5bfa2e803e0401fa750533dbeb059081eb03010e1fe82c00eb4b902e8b1e2e019c2eff1e3b01c3ff0800ea0500 }


condition:
	$a0
}