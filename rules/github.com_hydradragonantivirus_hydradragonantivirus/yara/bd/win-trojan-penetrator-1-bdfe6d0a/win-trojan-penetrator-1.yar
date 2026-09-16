rule Win_Trojan_Penetrator_1
{
strings:
	$a0 = { 5e83ee0356eb20905e2e83bc02020174050e680000c38bfe8cd80510002e0185be012effadbc01b8bafecd213d }


condition:
	$a0
}