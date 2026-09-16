rule Win_Trojan_LAVI_6
{
strings:
	$a0 = { 01b9340481e91601268a02340a26880246e2f5c3 }


condition:
	$a0
}