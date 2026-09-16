rule Win_Trojan_Subsys_5
{
strings:
	$a0 = { db21eb44ad103e5c863260af6076a432da70145113af86f22e6fc579683fef24 }


condition:
	$a0
}