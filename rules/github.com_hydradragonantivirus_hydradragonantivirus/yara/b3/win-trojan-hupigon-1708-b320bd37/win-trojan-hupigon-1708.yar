rule Win_Trojan_Hupigon_1708
{
strings:
	$a0 = { e81f0000005150b828d041006a006affff1089 }


condition:
	$a0
}