rule Win_Trojan_Rage_1
{
strings:
	$a0 = { 90b9fd018a24518ac8d2c4598824 }


condition:
	$a0
}