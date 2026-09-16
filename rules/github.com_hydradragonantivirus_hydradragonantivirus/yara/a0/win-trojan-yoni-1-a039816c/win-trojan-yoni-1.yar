rule Win_Trojan_Yoni_1
{
strings:
	$a0 = { 40cd217303eb50908bdfac8807ad8b47068b4f0403c18947015b538bd7b90300b80040cd2173 }


condition:
	$a0
}