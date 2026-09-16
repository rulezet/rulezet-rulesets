rule Win_Trojan_PS_MPCAlie_1
{
strings:
	$a0 = { b85e01bf21002e8135000047474875f6e800005d81ed24001e06b85643cd213d4b4c7465b44abbffffcd2183eb6090 }


condition:
	$a0
}