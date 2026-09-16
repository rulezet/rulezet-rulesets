rule Win_Trojan_Anti_18
{
strings:
	$a0 = { 740f803ede0302740c803ede0303 }


condition:
	$a0
}