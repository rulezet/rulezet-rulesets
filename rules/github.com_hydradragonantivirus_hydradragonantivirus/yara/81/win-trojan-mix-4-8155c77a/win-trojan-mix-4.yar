rule Win_Trojan_Mix_4
{
strings:
	$a0 = { 3500e81b00ba0000b9e808b4409c9a }


condition:
	$a0
}