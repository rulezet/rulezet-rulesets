rule Win_Trojan_Cheeba_A_1
{
strings:
	$a0 = { bf0001902e8035124781ff700772f5 }


condition:
	$a0
}