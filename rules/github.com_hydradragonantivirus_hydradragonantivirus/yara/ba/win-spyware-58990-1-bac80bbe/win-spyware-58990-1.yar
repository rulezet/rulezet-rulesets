rule Win_Spyware_58990_1
{
strings:
	$a0 = { 63746d31313030382e657865 }

	$a1 = { 420049004e }

	$a2 = { 7879325f65782e657865 }

	$a3 = { 2f7879322e696e69 }


condition:
	$a0 and $a1 and $a2 and $a3
}