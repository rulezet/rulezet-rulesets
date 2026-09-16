rule Win_Trojan_Fruit_1
{
strings:
	$a0 = { 8aa456078db42b018bfeb92b06ac32c402c4aa4975 }


condition:
	$a0
}