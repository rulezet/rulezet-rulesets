rule Win_Trojan_Sirius_14
{
strings:
	$a0 = { be1701ba0000b90000311490909090464690e2f590e800005d81ed1a01b8fefecd2181fe9419744733c08ed8c51e }


condition:
	$a0
}