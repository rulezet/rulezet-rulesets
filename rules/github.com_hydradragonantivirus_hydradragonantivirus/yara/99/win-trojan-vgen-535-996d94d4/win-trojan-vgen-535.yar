rule Win_Trojan_VGEN_535
{
strings:
	$a0 = { b9260281070000ec4343e2f7e800005d81ed1801e80e01b41a8d963203e8fe003ec6861903009083ec40558bec }


condition:
	$a0
}