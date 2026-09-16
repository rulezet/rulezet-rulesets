rule Win_Trojan_Seneca_1
{
strings:
	$a0 = { 1e7b02b97d01ba0001b440cd218b1e7b028b0e77028b167902b001b457cd218b1e7b02b43ecd21 }


condition:
	$a0
}