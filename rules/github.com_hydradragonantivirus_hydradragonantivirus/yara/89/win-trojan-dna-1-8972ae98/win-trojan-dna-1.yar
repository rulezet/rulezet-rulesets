rule Win_Trojan_DNA_1
{
strings:
	$a0 = { 5d83ed048a56008d5e279080fa00740f8af2b9770430172ad680ee2e43e2f6c3e8daff }


condition:
	$a0
}