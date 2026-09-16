rule Win_Trojan_W_314
{
strings:
	$a0 = { bf0008f7bfb973f5ffff870dc112f7bf80f90f7502f3a4cf663d4e71756060c8 }


condition:
	$a0
}