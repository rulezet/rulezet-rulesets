rule Win_Trojan_Clipper_1
{
strings:
	$a0 = { 7e4bbf0001be800503f72e8b8d2200 }


condition:
	$a0
}