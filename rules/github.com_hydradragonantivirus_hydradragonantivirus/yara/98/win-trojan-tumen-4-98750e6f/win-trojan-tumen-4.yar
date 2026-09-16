rule Win_Trojan_Tumen_4
{
strings:
	$a0 = { b4ffcd2180fcff74198b078a4f02a300 }


condition:
	$a0
}