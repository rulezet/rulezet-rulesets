rule Win_Trojan_Fiber_2
{
strings:
	$a0 = { c333c133c233c633c70bc00bc30bc10bc20bc60bc723c023c323c123c223c623c70e1fe800005b8d570e90b409 }


condition:
	$a0
}