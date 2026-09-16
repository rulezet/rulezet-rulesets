rule Win_Trojan_Istbar_205
{
strings:
	$a0 = { bab02840008b0d2c8040008b490c038df0feffffff1520114000 }


condition:
	$a0
}