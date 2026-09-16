rule Win_Trojan_VGEN_552
{
strings:
	$a0 = { ff444c5840587409b02ee670e671f4cd19b83f3acd2181fb2a3a750eeb6890235468455f57 }


condition:
	$a0
}