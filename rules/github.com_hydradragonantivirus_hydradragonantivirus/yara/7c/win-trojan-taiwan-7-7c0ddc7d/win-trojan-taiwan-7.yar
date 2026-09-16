rule Win_Trojan_Taiwan_7
{
strings:
	$a0 = { 268c0e5a0007e4210c02e621fbb9800033f6bb80008b0050 }


condition:
	$a0
}