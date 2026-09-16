rule Win_Trojan_Gen_79
{
strings:
	$a0 = { d2bb1000f7e303c183d200f7f35950b8 }


condition:
	$a0
}