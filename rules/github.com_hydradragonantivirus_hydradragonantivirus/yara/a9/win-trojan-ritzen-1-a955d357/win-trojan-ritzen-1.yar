rule Win_Trojan_Ritzen_1
{
strings:
	$a0 = { 505351521e0657569380ff3d741481fb004b740e5e5f071f }


condition:
	$a0
}