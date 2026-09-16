rule Win_Trojan_AAV_1
{
strings:
	$a0 = { 2a011e060e1f2e8c1e2c010e072e803e0b016d7512bb0003b80a02b90300ba8000cd13eb029056eb0190e83702 }


condition:
	$a0
}