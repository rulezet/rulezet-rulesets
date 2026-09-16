rule Win_Trojan_Sopron_1
{
strings:
	$a0 = { 40ba0001b9a90481e90001cd21e8c1ffb82125ba5002cd }


condition:
	$a0
}