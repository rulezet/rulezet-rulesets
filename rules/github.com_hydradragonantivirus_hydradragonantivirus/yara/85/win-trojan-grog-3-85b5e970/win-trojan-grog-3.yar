rule Win_Trojan_Grog_3
{
strings:
	$a0 = { d2b440cd2151b9f502ba0001b440cd21595803c13bc173 }


condition:
	$a0
}