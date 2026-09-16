rule Win_Trojan_DarkAvenger_4
{
strings:
	$a0 = { ac5188d1d2c8fec259aae2f407581fc301 }


condition:
	$a0
}