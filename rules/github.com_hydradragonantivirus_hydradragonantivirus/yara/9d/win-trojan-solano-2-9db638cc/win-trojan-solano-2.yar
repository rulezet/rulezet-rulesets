rule Win_Trojan_Solano_2
{
strings:
	$a0 = { 01b82425ba36042efe063e01cd212e }


condition:
	$a0
}