rule Win_Trojan_VB_388
{
strings:
	$a0 = { c745fc9e0000008d8dacfdffff518b55088b028b4d0851ff90040700008b95acfdffff5268ac414000ff1548104000 }


condition:
	$a0
}