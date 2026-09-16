rule Win_Trojan_Rajaat_5
{
strings:
	$a0 = { 03a14c0305a70283d200e86ffe89166503a36703b440ba6303b94400e8e8fee95aff }


condition:
	$a0
}