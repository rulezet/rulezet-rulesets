rule Win_Trojan_Sopwith_1
{
strings:
	$a0 = { 0db440b9d6028bd681eafc01cd2172 }


condition:
	$a0
}