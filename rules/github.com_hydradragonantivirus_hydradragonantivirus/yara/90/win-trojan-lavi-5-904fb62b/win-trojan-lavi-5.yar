rule Win_Trojan_LAVI_5
{
strings:
	$a0 = { 01b9320481e91601268a02346426880246e2f5c3 }


condition:
	$a0
}