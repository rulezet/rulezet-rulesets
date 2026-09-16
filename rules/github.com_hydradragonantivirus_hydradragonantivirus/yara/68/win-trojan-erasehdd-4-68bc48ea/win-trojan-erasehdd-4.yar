rule Win_Trojan_EraseHDD_4
{
strings:
	$a0 = { 100333db33d280c298b91800feca51b90100cd1359e2f5cd20 }


condition:
	$a0
}