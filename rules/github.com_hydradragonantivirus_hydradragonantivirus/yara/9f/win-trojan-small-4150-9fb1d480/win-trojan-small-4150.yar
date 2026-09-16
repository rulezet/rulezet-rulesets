rule Win_Trojan_Small_4150
{
strings:
	$a0 = { eb16c351ffd1816c0500c2ab23344545454539 }


condition:
	$a0
}