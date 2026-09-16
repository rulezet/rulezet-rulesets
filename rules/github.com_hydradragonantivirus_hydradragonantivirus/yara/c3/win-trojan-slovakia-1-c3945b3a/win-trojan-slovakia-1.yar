rule Win_Trojan_Slovakia_1
{
strings:
	$a0 = { 028bf28a238b163e0ffceb4590cd138a22b40081e1 }


condition:
	$a0
}