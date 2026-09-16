rule Win_Trojan_Small_4581
{
strings:
	$a0 = { b8????????8bc85083c032c3bb }


condition:
	$a0
}