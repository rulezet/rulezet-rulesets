rule Win_Trojan_PhVx_1
{
strings:
	$a0 = { d2b98304e835003bc17404f9eb079032c0e82e00f8c3b8 }


condition:
	$a0
}