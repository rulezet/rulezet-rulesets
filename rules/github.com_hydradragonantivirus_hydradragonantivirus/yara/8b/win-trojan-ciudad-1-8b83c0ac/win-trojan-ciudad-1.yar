rule Win_Trojan_Ciudad_1
{
strings:
	$a0 = { 40b94e029033d2cd212ea1cd00538bd8b104d3eb83c338 }


condition:
	$a0
}