rule Win_Trojan_Haha_1
{
strings:
	$a0 = { b8280050b80100505633c050b8800050b8050050e8c10b83c40e8bf84683fe607ed90bff75108d86 }


condition:
	$a0
}