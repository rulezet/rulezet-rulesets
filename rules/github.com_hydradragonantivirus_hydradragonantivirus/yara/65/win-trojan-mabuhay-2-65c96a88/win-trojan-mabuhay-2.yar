rule Win_Trojan_Mabuhay_2
{
strings:
	$a0 = { b40dcd21b00050b90001ba0000cd269d58fec03c0272efb00250b9ffffba0000cd269d58 }


condition:
	$a0
}