rule Win_Trojan_DBCE_2
{
strings:
	$a0 = { 0b0050cbbe450d4e2e800407ebf9adf7c61aff79f5626d15ad23c61a7af2c2006d547af2c300 }


condition:
	$a0
}