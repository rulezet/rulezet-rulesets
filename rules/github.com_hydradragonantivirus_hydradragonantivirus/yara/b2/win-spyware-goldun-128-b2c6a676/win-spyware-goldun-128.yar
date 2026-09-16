rule Win_Spyware_Goldun_128
{
strings:
	$a0 = { 7470733a2f2fb5652d676f6c6aad17dd642e2c2fb4463cb56fc796216451 }


condition:
	$a0
}