rule Win_Trojan_Internal_3
{
strings:
	$a0 = { c88ed8b840008ec0fce8a604803eaf0000740be8c1 }


condition:
	$a0
}