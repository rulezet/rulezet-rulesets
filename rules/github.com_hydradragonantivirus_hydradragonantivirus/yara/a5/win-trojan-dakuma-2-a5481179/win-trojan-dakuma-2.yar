rule Win_Trojan_Dakuma_2
{
strings:
	$a0 = { b80103b70230db30edb10eb280cd13cd20 }


condition:
	$a0
}