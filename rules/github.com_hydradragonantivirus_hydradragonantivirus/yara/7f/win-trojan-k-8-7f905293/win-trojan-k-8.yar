rule Win_Trojan_K_8
{
strings:
	$a0 = { b63502b9a701f61446e2fbc3cd12b90004f7e1b91000f7f1c3a6908adf979e899adf8b979adfb5 }


condition:
	$a0
}