rule Win_Trojan_Hydra_14
{
strings:
	$a0 = { b43db002ba5301cd218bd8061fb8003fb9ffffbaef01cd21 }


condition:
	$a0
}