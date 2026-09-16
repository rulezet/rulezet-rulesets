rule Win_Trojan_Peed_242
{
strings:
	$a0 = { e8210000005589e5518b7d18ab83ef04e2f7592b55082b550c035510 }


condition:
	$a0
}