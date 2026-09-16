rule Win_Trojan_Fight_1
{
strings:
	$a0 = { ffb8030050e8ec0000000100558bec81ec0202c746fe0000eb10ba70008a46feeeba7100b000 }


condition:
	$a0
}