rule Win_Trojan_Paulus_1
{
strings:
	$a0 = { 8bdedc892706538c3f0786ca922e86ca2e88074a }


condition:
	$a0
}