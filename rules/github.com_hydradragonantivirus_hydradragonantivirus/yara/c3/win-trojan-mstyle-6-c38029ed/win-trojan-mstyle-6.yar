rule Win_Trojan_Mstyle_6
{
strings:
	$a0 = { 082e93a790d67789c96c7ae519c708b26e61cb1afdcc40a0705aec525b52 }


condition:
	$a0
}