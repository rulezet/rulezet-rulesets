rule Win_Trojan_B_241
{
strings:
	$a0 = { 33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfb60b9??01bd2a06d24e0045e2fa }


condition:
	$a0
}