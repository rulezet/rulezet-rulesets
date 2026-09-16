rule Win_Trojan_Small_174
{
strings:
	$a0 = { 5626a526a55fb84e02ab91ab5e0781c64a00580be4 }


condition:
	$a0
}