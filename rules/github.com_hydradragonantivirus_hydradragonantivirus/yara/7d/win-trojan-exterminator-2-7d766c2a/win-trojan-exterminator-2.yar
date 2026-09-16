rule Win_Trojan_Exterminator_2
{
strings:
	$a0 = { 7801b90b11b44ecd217302eb1eba9e }


condition:
	$a0
}