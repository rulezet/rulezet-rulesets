rule Win_Trojan_SillyC_75
{
strings:
	$a0 = { b70083f31683f316803dbe74bd83c30983eb095033c9b8004299cd21040e2c0e59b470b440cd21 }


condition:
	$a0
}