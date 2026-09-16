rule Win_Dropper_Small_1909
{
strings:
	$a0 = { e87f0000006a006a066a026a006a006800000040ff750ce8fe000000 }


condition:
	$a0
}