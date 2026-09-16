rule Win_Trojan_Jorgito_1
{
strings:
	$a0 = { cd213d83787455b82135cd212e891ef6012e8c06 }


condition:
	$a0
}