rule Win_Trojan_SillyC_78
{
strings:
	$a0 = { b4408bd7cd21b8004233c999cd21582d0300a32600b440ba2500b90300cd21b80057cd2133 }


condition:
	$a0
}