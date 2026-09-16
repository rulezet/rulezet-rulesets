rule Win_Trojan_Carmel_1
{
strings:
	$a0 = { 8ec08ed8fcbe13048bfead48abc1e0068ec08bf48ccfe86600b9fc00f2a4bb3400eb1245 }


condition:
	$a0
}