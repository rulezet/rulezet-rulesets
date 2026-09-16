rule Win_Trojan_Leepload_1
{
strings:
	$a0 = { 68696e742e6861707079666f72657665722e636f6d }


condition:
	$a0
}