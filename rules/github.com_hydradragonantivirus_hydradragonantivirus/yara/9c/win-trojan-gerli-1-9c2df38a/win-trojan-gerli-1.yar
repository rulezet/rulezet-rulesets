rule Win_Trojan_Gerli_1
{
strings:
	$a0 = { 01b9bd0481e90f01268a023286bc0426880246e2f3 }


condition:
	$a0
}