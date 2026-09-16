rule Win_Trojan_DrDemon_3
{
strings:
	$a0 = { a88abfb86e7896c97e296204c9176db56ed7878aa637bebc6c06d98462bd6204ad1759bc2e020dcf }


condition:
	$a0
}