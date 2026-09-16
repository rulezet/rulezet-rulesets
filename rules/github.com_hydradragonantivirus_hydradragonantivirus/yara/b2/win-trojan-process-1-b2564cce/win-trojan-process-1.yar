rule Win_Trojan_Process_1
{
strings:
	$a0 = { 20018b6e008ba602008b9e0400b44acd21a12c0089861a008b9e0000ffe387048a14460ad27406b402cd21ebf3c3 }


condition:
	$a0
}