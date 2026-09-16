rule Win_Trojan_Stoned_37
{
strings:
	$a0 = { fa33ff8edf8ed7bc007c8bf4fb56ff0e1304cd12b106d3e050bb03018ec0b90001f3a553cb }


condition:
	$a0
}