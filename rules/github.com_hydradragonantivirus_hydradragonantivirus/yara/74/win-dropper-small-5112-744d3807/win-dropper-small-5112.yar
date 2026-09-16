rule Win_Dropper_Small_5112
{
strings:
	$a0 = { b828674000baa44e4000e8f7e1ffffb828674000bab44e4000e8e8e1ffffb828674000bac44e4000e8d9e1ffffb828674000bad44e4000e8cae1ffffbae04e4000a128674000e8abfdffff }


condition:
	$a0
}