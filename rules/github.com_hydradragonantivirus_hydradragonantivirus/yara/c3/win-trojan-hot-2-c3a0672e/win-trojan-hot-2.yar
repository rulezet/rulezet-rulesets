rule Win_Trojan_Hot_2
{
strings:
	$a0 = { 04dac4bf20dac4bf20dac4c4c4c4c4c4bf20dac4bf20dac4bf2020202020dac4c4c4c4c4c4bf20dac4c4c4c4c4c4 }


condition:
	$a0
}