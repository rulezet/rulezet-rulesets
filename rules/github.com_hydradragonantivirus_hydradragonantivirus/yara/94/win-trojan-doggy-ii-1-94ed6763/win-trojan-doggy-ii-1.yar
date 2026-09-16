rule Win_Trojan_Doggy_II_1
{
strings:
	$a0 = { 3962e6d9993b929522b01ad9e3db5421bdde51328e983f86f4d93f755c5534852419443d807e }


condition:
	$a0
}