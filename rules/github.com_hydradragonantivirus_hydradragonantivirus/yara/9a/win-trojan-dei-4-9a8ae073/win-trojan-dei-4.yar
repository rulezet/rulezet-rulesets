rule Win_Trojan_Dei_4
{
strings:
	$a0 = { fba1b508e84a00babd08b91c00b440e8cefb26c74515000026c745170000baa108b440e8bafb }


condition:
	$a0
}