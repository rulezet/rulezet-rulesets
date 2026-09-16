rule Win_Trojan_Animals_1
{
strings:
	$a0 = { c7061900bf290e1f81361b00aeb1fdc7061d00060ec7061f0007b9f7162100c7062300bb130e1f81362500a3d7e9aef6 }


condition:
	$a0
}