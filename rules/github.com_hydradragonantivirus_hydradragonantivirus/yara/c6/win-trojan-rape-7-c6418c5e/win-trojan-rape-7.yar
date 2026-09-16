rule Win_Trojan_Rape_7
{
strings:
	$a0 = { 140bac5188d1d2c0fec259aae2f407581fc301 }


condition:
	$a0
}