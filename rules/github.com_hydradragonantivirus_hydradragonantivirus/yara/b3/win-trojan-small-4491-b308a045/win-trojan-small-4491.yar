rule Win_Trojan_Small_4491
{
strings:
	$a0 = { 5589e531c05089e7b800??4000abe81b000000e821000000030683c60481f0 }


condition:
	$a0
}