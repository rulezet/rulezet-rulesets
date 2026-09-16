rule Win_Trojan_N_10
{
strings:
	$a0 = { 8bf4368b2ccc81ed03001e06e88002e260cdc57b89a14a0d7c22849a40d4d069f7da35007d36ce5f45d9655926 }


condition:
	$a0
}