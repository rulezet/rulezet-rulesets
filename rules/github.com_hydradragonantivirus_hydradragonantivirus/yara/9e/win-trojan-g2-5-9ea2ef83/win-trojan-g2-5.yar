rule Win_Trojan_G2_5
{
strings:
	$a0 = { 0300061eb84144cd213d6d687458b44abbffffcd2183eb2490b44acd217247832e02002490b448bb2300cd2172 }


condition:
	$a0
}