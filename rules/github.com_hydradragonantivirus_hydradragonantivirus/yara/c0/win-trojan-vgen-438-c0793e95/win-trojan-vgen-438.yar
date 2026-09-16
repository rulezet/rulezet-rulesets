rule Win_Trojan_VGEN_438
{
strings:
	$a0 = { c706fd00ffff813e0000cd206a001f7568b4fbcd137315e8c0000e0e07e88600b42acd2180fe00 }


condition:
	$a0
}