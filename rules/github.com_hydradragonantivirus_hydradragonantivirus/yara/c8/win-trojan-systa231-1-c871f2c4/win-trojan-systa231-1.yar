rule Win_Trojan_SYSTA231_1
{
strings:
	$a0 = { 58722989450889440db440b9e70089f2cd21b8004233c999cd21b440b90a008d94e700cd21 }


condition:
	$a0
}