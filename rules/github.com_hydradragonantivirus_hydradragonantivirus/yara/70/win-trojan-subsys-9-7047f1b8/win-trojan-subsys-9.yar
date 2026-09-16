rule Win_Trojan_Subsys_9
{
strings:
	$a0 = { 462ccc2bccfd5bb30f516b2939d99d785e7fda2c03f15b1f118ca8e7d1f87f0923a0cf3abfa44c93def4e0d289528e241f94de84ab506b3353 }


condition:
	$a0
}