rule Win_Trojan_SySta_1
{
strings:
	$a0 = { e70089f2cd21b8004233c999cd21b440b90a008d94e700cd21b43ecd21e90800b43ecd21b4 }


condition:
	$a0
}