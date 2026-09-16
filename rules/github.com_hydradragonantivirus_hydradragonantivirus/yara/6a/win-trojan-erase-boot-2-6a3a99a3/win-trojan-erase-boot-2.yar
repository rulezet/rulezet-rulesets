rule Win_Trojan_Erase_boot_2
{
strings:
	$a0 = { 03bb007cb90100ba0100cd13b80103cd13c3 }


condition:
	$a0
}