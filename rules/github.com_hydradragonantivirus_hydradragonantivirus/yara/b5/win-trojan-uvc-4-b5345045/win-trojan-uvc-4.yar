rule Win_Trojan_Uvc_4
{
strings:
	$a0 = { 81f1ebe481f1471981c1028281c1df9481e9e1b681f17495ba5802cd21b854d235c24a3512 }


condition:
	$a0
}