rule Win_Trojan_Havoc_5
{
strings:
	$a0 = { 8ed0bc007cfb8ec40668160293b80902b90250ba0000cd1372fecb }


condition:
	$a0
}