rule Win_Trojan_Milan_3
{
strings:
	$a0 = { 3dcd2172cc8bd8b80057cd2189160701890e0901ba00 }


condition:
	$a0
}