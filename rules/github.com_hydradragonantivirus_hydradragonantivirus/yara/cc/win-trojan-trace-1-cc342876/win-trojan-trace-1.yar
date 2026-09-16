rule Win_Trojan_Trace_1
{
strings:
	$a0 = { d7cd218bd683c205b9d00bb440cd21 }


condition:
	$a0
}