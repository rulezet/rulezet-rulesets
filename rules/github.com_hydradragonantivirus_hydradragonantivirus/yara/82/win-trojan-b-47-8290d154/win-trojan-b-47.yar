rule Win_Trojan_B_47
{
strings:
	$a0 = { ba8000b90100bb0002cd13813ee802007c741bb80103bb0002b90a00cd1372 }


condition:
	$a0
}