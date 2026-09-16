rule Win_Trojan_Hydra_5
{
strings:
	$a0 = { b43db002ba5301b002cd218bd8061fb8003fb9ffffba5601 }


condition:
	$a0
}