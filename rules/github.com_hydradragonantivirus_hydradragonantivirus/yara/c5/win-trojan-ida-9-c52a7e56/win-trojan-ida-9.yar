rule Win_Trojan_Ida_9
{
strings:
	$a0 = { b8addecd2181ff961974[0-100]b82135cd21[0-100]b82125cd21 }


condition:
	$a0
}