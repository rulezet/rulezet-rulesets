rule Win_Trojan_SillyRC_34
{
strings:
	$a0 = { 83c91f5152b44033d2b9650151e81f00b8004233c933d2e81500b4400e1fba000159e80a00 }


condition:
	$a0
}