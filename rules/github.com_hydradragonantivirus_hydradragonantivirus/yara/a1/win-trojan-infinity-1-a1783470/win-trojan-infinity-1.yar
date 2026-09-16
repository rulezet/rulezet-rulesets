rule Win_Trojan_Infinity_1
{
strings:
	$a0 = { b440b9dc02908bd681ea1402cd21 }


condition:
	$a0
}