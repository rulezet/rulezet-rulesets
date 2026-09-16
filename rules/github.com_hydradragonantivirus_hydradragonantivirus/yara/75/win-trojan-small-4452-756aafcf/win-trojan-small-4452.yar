rule Win_Trojan_Small_4452
{
strings:
	$a0 = { 6853530400b8ff89bffff7d089e28902ba8238450052505155e8 }


condition:
	$a0
}