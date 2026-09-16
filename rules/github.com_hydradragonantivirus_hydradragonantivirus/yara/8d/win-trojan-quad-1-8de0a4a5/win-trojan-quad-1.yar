rule Win_Trojan_Quad_1
{
strings:
	$a0 = { 04a3dd04b440b9d503ba0301cd2126c74515000026c745170000b440b91a00bad904cd21 }


condition:
	$a0
}