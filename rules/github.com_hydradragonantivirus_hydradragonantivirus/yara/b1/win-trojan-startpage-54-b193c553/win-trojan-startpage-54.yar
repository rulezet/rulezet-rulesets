rule Win_Trojan_Startpage_54
{
strings:
	$a0 = { c1c21d0fb6dab880404000f7dbeb013d8d35f4000000eb015180f31c0fbed20fb6d28b38eb02234feb01e4eb029ee6eb }


condition:
	$a0
}