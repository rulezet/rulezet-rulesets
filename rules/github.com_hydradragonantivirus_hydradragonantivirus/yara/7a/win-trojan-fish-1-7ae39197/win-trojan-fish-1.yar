rule Win_Trojan_Fish_1
{
strings:
	$a0 = { 0e2e8326db0efe2e803eda0e0075112eff36db0e }


condition:
	$a0
}