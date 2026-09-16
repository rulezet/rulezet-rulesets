rule Win_Trojan_CryptoLocker_3
{
strings:
	$a0 = { 558bec515356578bf98d770c56ff15a4914100837f08007560 }


condition:
	$a0
}