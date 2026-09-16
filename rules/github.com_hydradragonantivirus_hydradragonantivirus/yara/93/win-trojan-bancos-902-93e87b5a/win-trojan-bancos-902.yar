rule Win_Trojan_Bancos_902
{
strings:
	$a0 = { c3247260975d2fea07d4ad3480ae6dd9157880be99631ee3176efc534cf4e9063a0ac8247bed7486faca49f8743db9e8fd589c588f4052ca435b85e9cf0905dda2420d7e2cd336c8cad698fb4eb9 }


condition:
	$a0
}