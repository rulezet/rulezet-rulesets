rule Win_Trojan_VGEN_575
{
strings:
	$a0 = { 28ba8c012e8107292743434a75f6bfd9d73558c6f0d8f5de8f1485a6f859d201a44d1065972165b15807dad857d9 }


condition:
	$a0
}