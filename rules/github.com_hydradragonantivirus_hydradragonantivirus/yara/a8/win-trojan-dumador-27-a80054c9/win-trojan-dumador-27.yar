rule Win_Trojan_Dumador_27
{
strings:
	$a0 = { 61c983c404558bec6a136800000000c3c804000081fb47414c46741f60ff7518ff7514ff7510ff750ce8 }


condition:
	$a0
}