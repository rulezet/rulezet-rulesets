rule Win_Trojan_CyberShadow_1
{
strings:
	$a0 = { 8bd62bc9b44ecd215e5f813e9a0048ee775fba9e00b8023dcd2172558bd88bd68bcdb43fcd21 }


condition:
	$a0
}