rule Win_Trojan_Waledac_36
{
strings:
	$a0 = { c1d802b866000000c1e903b94b00000013c2c1da0cbaae000000c1c10e }


condition:
	$a0
}