rule Win_Trojan_SVC_7
{
strings:
	$a0 = { b80143e898ffb8023de892ff729c8b }


condition:
	$a0
}