rule Win_Spyware_58989_1
{
strings:
	$a0 = { 63746d30333030342e657865[0-40]61736b74616f2e6d6f64 }

	$a1 = { 54726f6a616e41736b74616f2e646c6c }


condition:
	$a0 and $a1
}