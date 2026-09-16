rule Win_Trojan_Krile_2
{
strings:
	$a0 = { b4e971ed73d116aaa16ce3c42d7f395cdf79ae482148df84096f7c7fb4b66d82406eb229e4 }


condition:
	$a0
}