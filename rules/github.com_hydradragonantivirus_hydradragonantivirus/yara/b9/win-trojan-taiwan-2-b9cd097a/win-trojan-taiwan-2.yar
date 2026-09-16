rule Win_Trojan_Taiwan_2
{
strings:
	$a0 = { e4210c02e621fbb9800033f6bb8000 }


condition:
	$a0
}