rule Win_Trojan_Bifrose_698
{
strings:
	$a0 = { c85223eeba86144ecaff80151ae94d39e61200ae3438c276edde00d84b7fc8d7db9bc400f6bafad0b65681cd0e5913eb05815e01c1bbc3e839d8ba00a764a89a41adb7f9 }


condition:
	$a0
}