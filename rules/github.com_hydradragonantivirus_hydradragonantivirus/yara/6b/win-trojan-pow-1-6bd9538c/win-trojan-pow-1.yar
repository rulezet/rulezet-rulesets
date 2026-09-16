rule Win_Trojan_Pow_1
{
strings:
	$a0 = { ff8edf8ed7bc007cbe120446ff0cadb106d3e08ec0fc8bf4b9fe00f3a5be4c00a5a5c744fc81008c44fefbcd192d }


condition:
	$a0
}