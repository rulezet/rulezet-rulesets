rule Win_Trojan_N_25
{
strings:
	$a0 = { 820b8f2c368ebf0d8fd2b97903ec70f79b097b6a42390b726b502e1d57245354 }


condition:
	$a0
}